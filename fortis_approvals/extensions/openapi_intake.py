"""Offline, bounded OpenAPI 3.0/3.1 GET/JSON *draft* intake for Fortis.

Never fetches a spec/URL, resolves external refs, runs code, obtains secrets,
asserts review, changes policy, registers a provider, or sends HTTP requests.
An imported method is always UNREVIEWED until independently verified source
and upstream fixtures pass the ordinary Fortis onboarding/source gates.
"""
import argparse
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import re

from ..core import Denied, canonical, loads_strict
from .declarative_read import _value_schema
from .model import check, ident, TARGET, IDENT, RESERVED
from .source_generator import render_package

_PATH_PLACEHOLDER=re.compile(r'\{([a-z][a-z0-9_]*)\}')
_FIELD=re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
_COMPONENT_NAME=re.compile(r'[A-Za-z0-9_.-]{1,80}\Z')
_MAX_SPEC_BYTES=262144
_MAX_DEPTH=7
_MAX_NODES=128
_MAX_OPERATIONS=64
_METHODS={'get','post','put','patch','delete','head','options','trace'}
_SCHEMA_ANNOTATIONS = {'title', 'description', 'deprecated', 'example',
                       'examples', 'default', 'readOnly', 'writeOnly'}
_SCHEMA_ALLOWED = _SCHEMA_ANNOTATIONS | {
    'type', 'nullable', 'properties', 'required', 'items', 'minLength',
    'maxLength', 'minimum', 'maximum', 'enum', 'const', 'format',
    'maxItems', 'minItems', 'additionalProperties',
}
_FORBIDDEN_FIELDS={'token','accesstoken','refreshtoken','apikey','authorization',
                   'credential','credentials','secret','password','privatekey'}


class _Gap(Exception):
    def __init__(self,code):self.code=code


def _reject(cond,code):
    if not cond:raise _Gap(code)


def _normalize(document):
    try:
        if type(document) in (bytes,str):
            check(len(document if type(document) is bytes else
                      document.encode('utf-8'))<=_MAX_SPEC_BYTES,
                  'OPENAPI_DOCUMENT_TOO_LARGE')
            value=loads_strict(document)
        else:
            raw=canonical(document)
            check(len(raw.encode('utf-8'))<=_MAX_SPEC_BYTES,
                  'OPENAPI_DOCUMENT_TOO_LARGE')
            value=loads_strict(raw)
    except Denied:
        raise
    except (TypeError,ValueError,UnicodeError,RecursionError):
        raise Denied('OPENAPI_DOCUMENT_INVALID_JSON') from None
    check(type(value) is dict and type(value.get('openapi')) is str and
          re.fullmatch(r'3\.(0|1)\.[0-9]+',value['openapi']) is not None and
          type(value.get('info')) is dict and
          type(value['info'].get('title')) is str and bool(value['info']['title']) and
          type(value['info'].get('version')) is str and bool(value['info']['version']) and
          type(value.get('paths')) is dict and
          1<=len(value['paths'])<=_MAX_OPERATIONS,
          'OPENAPI_DOCUMENT_UNSUPPORTED')
    return value


def _reference(document,value,section,visited):
    """Resolve ONLY a direct local named component, with cycle detection."""
    if type(value) is not dict:raise _Gap('OPENAPI_SCHEMA_INVALID')
    if '$ref' not in value:return value,visited
    _reject(set(value)=={'$ref'} and type(value['$ref']) is str,
            'OPENAPI_REFERENCE_SIBLINGS_UNSUPPORTED')
    prefix='#/components/'+section+'/'
    ref=value['$ref']
    _reject(ref.startswith(prefix) and _COMPONENT_NAME.fullmatch(ref[len(prefix):]),
            'OPENAPI_EXTERNAL_OR_COMPLEX_REF_UNSUPPORTED')
    _reject(ref not in visited and len(visited)<_MAX_DEPTH,
            'OPENAPI_REFERENCE_CYCLE_OR_DEPTH')
    obj=document.get('components',{});
    _reject(type(obj) is dict and type(obj.get(section)) is dict and
            ref[len(prefix):] in obj[section], 'OPENAPI_LOCAL_REFERENCE_MISSING')
    return _reference(document,obj[section][ref[len(prefix):]],section,
                      visited|{ref})


class _Shape:
    def __init__(self,document):
        self.document=document
        self.nodes=0

    def read(self,value,*,depth=0,visited=frozenset(),nested=False):
        self.nodes+=1
        _reject(self.nodes<=_MAX_NODES and depth<=_MAX_DEPTH,
                'OPENAPI_SCHEMA_COMPLEXITY')
        node,visited=_reference(self.document,value,'schemas',visited)
        _reject(all(key in _SCHEMA_ALLOWED or key.startswith('x-')
                    for key in node), 'OPENAPI_SCHEMA_KEYWORD_UNSUPPORTED')
        _reject(not node.get('writeOnly',False),
                'OPENAPI_WRITE_ONLY_RESPONSE_REVIEW_REQUIRED')
        kind=node.get('type')
        nullable=node.get('nullable',False)
        _reject(type(nullable) is bool,'OPENAPI_NULLABLE_INVALID')
        if type(kind) is list:
            _reject(len(kind)==2 and kind.count('null')==1 and
                    all(type(x) is str for x in kind),
                    'OPENAPI_UNION_UNSUPPORTED')
            kind=next(x for x in kind if x!='null')
            nullable=True
        _reject(type(kind) is str and kind!='null',
                'OPENAPI_SCHEMA_TYPE_UNSUPPORTED')
        if 'const' in node:
            _reject(all(key in _SCHEMA_ANNOTATIONS or key in {'type', 'nullable', 'const'}
                        or key.startswith('x-') for key in node),
                    'OPENAPI_CONST_CONSTRAINTS_REVIEW_REQUIRED')
            const=node['const']
            _reject(type(const) in (str,int,bool) and (type(const) is not str or
                    0<len(const)<=256),'OPENAPI_CONST_UNSUPPORTED')
            _reject((kind=='string' and type(const) is str) or
                    (kind=='integer' and type(const) is int) or
                    (kind=='boolean' and type(const) is bool),
                    'OPENAPI_CONST_UNSUPPORTED')
            return {'type': 'literal', 'equals': const}, None
        elif kind=='object':
            _reject(not nullable,'OPENAPI_NULLABLE_OBJECT_UNSUPPORTED')
            _reject(not nested,'OPENAPI_NESTED_OBJECT_PROJECTION_UNSUPPORTED')
            return self.object(node,depth=depth,visited=visited)
        elif kind=='array':
            maximum=node.get('maxItems')
            _reject(type(maximum) is int and 0<=maximum<=256,
                    'OPENAPI_ARRAY_NEEDS_BOUNDED_MAXITEMS')
            _reject('minItems' not in node or
                    type(node['minItems']) is int and node['minItems']==0,
                    'OPENAPI_MINITEMS_UNSUPPORTED')
            _reject('items' in node,'OPENAPI_ARRAY_ITEMS_REQUIRED')
            items,projection=self.read(node['items'],depth=depth+1,
                                       visited=visited,nested=False)
            internal={'type':'array','maxItems':maximum,'items':items}
            if nullable:raise _Gap('OPENAPI_NULLABLE_ARRAY_PROJECTION_UNSUPPORTED')
            return internal,projection
        elif kind=='string':
            maximum=node.get('maxLength')
            minimum=node.get('minLength',0)
            _reject(type(maximum) is int and type(minimum) is int and
                    0<=minimum<=maximum<=65536,
                    'OPENAPI_STRING_NEEDS_LENGTH_BOUNDS')
            _reject(node.get('format') in (None,''),
                    'OPENAPI_STRING_FORMAT_REVIEW_REQUIRED')
            _reject('enum' not in node,
                    'OPENAPI_STRING_ENUM_REVIEW_REQUIRED')
            internal={'type':'string','minLength':minimum,'maxLength':maximum,
                      'unit':'codepoints','printable':False,'format':None}
        elif kind=='integer':
            lo,hi=node.get('minimum'),node.get('maximum')
            fmt=node.get('format')
            _reject(fmt in (None,'int32','int64'),
                    'OPENAPI_INTEGER_FORMAT_UNSUPPORTED')
            _reject((lo is None or type(lo) is int) and
                    (hi is None or type(hi) is int) and
                    (lo is None or hi is None or lo<=hi),
                    'OPENAPI_INTEGER_LIMIT_INVALID')
            if fmt is not None:
                bits=32 if fmt=='int32' else 64
                lo=max(-2**(bits-1),lo) if lo is not None else -2**(bits-1)
                hi=min(2**(bits-1)-1,hi) if hi is not None else 2**(bits-1)-1
            _reject(lo is None or hi is None or lo<=hi,
                    'OPENAPI_INTEGER_LIMIT_INVALID')
            choices=node.get('enum')
            _reject(choices is None or (type(choices) is list and
                    0<len(choices)<=100 and all(type(x) is int for x in choices) and
                    len(set(choices))==len(choices)),
                    'OPENAPI_INTEGER_ENUM_UNSUPPORTED')
            internal={'type':'integer','minimum':lo,'maximum':hi,'choices':choices}
            # An integer-only enum excludes null even when the type allows it.
            nullable = nullable and choices is None
        elif kind=='boolean':
            _reject('enum' not in node,'OPENAPI_BOOL_ENUM_UNSUPPORTED')
            internal={'type':'boolean','equals':None}
        else:
            raise _Gap('OPENAPI_SCHEMA_TYPE_UNSUPPORTED')
        return ({'type':'nullable','item':internal} if nullable else internal),None

    def object(self,value,*,depth=0,visited=frozenset()):
        node,visited=_reference(self.document,value,'schemas',visited)
        _reject(all(key in _SCHEMA_ALLOWED or key.startswith('x-')
                    for key in node), 'OPENAPI_SCHEMA_KEYWORD_UNSUPPORTED')
        _reject((node.get('nullable') is None or
                 node.get('nullable') is False) and
                node.get('type')=='object' and
                type(node.get('properties')) is dict,
                'OPENAPI_RESPONSE_OBJECT_REQUIRED')
        required=node.get('required',[])
        _reject(type(required) is list and bool(required) and
                all(type(x) is str and x in node['properties'] for x in required) and
                len(required)==len(set(required)),
                'OPENAPI_REQUIRED_RESULT_FIELDS_UNAVAILABLE')
        _reject(len(required)<=25, 'OPENAPI_SCHEMA_TOO_MANY_FIELDS')
        fields={};projection={}
        for key in sorted(required):
            _reject(_FIELD.fullmatch(key) and
                    key.lower().replace('_','').replace('-','') not in _FORBIDDEN_FIELDS,
                    'OPENAPI_SENSITIVE_OR_UNMAPPABLE_FIELD')
            child,child_projection=self.read(node['properties'][key],
                          depth=depth+1,visited=visited,nested=True)
            fields[key]=child
            projection[key]=({'array':key,'fields':child_projection}
                             if child_projection is not None else key)
        return {'type':'object','fields':fields},projection


def _path(path):
    _reject(type(path) is str and path.startswith('/') and
            not path.startswith('//') and len(path)<=256 and
            all(33<=ord(ch)<127 for ch in path) and
            not any(x in path for x in ('?','#','\\','%','//')) and
            all(part not in ('.','..') for part in path.split('/')),
            'OPENAPI_ROUTE_UNSAFE')
    # Validate every brace, not only the recognized placeholders.
    params=_PATH_PLACEHOLDER.findall(path)
    _reject(path.count('{')==len(params)==path.count('}') and
            len(params)==len(set(params)) and len(params)<=1,
            'OPENAPI_PATH_PARAMETER_BINDING_REVIEW_REQUIRED')
    return params


def _path_target_schema(document, schema):
    node, _ = _reference(document, schema, 'schemas', frozenset())
    kind = node.get('type')
    _reject(kind in ('string', 'integer'), 'OPENAPI_PATH_PARAM_TYPE_UNSUPPORTED')
    if kind == 'string':
        # Unbounded OpenAPI strings still use Fortis's bounded target identifiers.
        node = {'maxLength': 65536, **node}
    shape, _ = _Shape(document).read(node)
    _reject(shape['type'] == kind, 'OPENAPI_PATH_PARAM_SCHEMA_REVIEW_REQUIRED')
    return shape


def _parameters(document,path_item,operation,placeholders):
    inherited=path_item.get('parameters',[])
    own=operation.get('parameters',[])
    _reject(type(inherited) is list and type(own) is list and
            len(inherited)+len(own)<=20,'OPENAPI_PARAMETERS_INVALID')
    rows=inherited+own
    seen=set();fields={};mapping={};path_seen=set()
    path_schema = None
    for raw in rows:
        row,_=_reference(document,raw,'parameters',frozenset())
        _reject(type(row.get('name')) is str and type(row.get('in')) is str,
                'OPENAPI_PARAMETER_INVALID')
        name=row['name'];location=row['in']
        _reject((name,location) not in seen,'OPENAPI_DUPLICATE_PARAMETER_REVIEW_REQUIRED')
        seen.add((name,location))
        _reject(IDENT.fullmatch(name) and
                name.lower().replace('_','').replace('-','') not in _FORBIDDEN_FIELDS,
                'OPENAPI_UNSAFE_PARAMETER_NAME')
        _reject(type(row.get('required',False)) is bool,
                'OPENAPI_PARAMETER_REQUIRED_INVALID')
        _reject('content' not in row and 'schema' in row and
                type(row['schema']) is dict and
                row.get('style') in (None,'form','simple') and
                row.get('explode') in (None,False,True),
                'OPENAPI_PARAMETER_SERIALIZATION_UNSUPPORTED')
        if location=='path':
            _reject(row.get('style') in (None,'simple') and
                    row.get('explode') in (None,False) and
                    row.get('allowReserved') in (None,False),
                    'OPENAPI_PATH_ENCODING_UNSUPPORTED')
            _reject(name in placeholders and row.get('required') is True,
                    'OPENAPI_PATH_PARAM_UNBOUND')
            path_seen.add(name)
            path_schema = _path_target_schema(document, row['schema'])
        elif location=='query':
            _reject(row.get('style') in (None,'form') and
                    row.get('explode') in (None,True) and
                    row.get('allowReserved') in (None,False) and
                    row.get('allowEmptyValue') in (None,False),
                    'OPENAPI_QUERY_ENCODING_UNSUPPORTED')
            shaper=_Shape(document)
            shape,_=shaper.read(row['schema'])
            _reject(shape['type'] in ('string','integer','boolean'),
                    'OPENAPI_QUERY_SCALAR_ONLY')
            if row.get('required',False) is not True:
                shape={'type':'nullable','item':shape}
            fields[name]=shape;mapping[name]=name
        else:
            raise _Gap('OPENAPI_HEADER_OR_COOKIE_PARAM_REVIEW_REQUIRED')
    _reject(set(placeholders)==path_seen,'OPENAPI_PATH_PARAM_UNBOUND')
    return fields, mapping, path_schema


def _operation(document,path,path_item,name,operation):
    _reject(type(operation) is dict,'OPENAPI_OPERATION_INVALID')
    _reject('requestBody' not in operation, 'OPENAPI_GET_REQUEST_BODY_UNSUPPORTED')
    _reject('servers' not in operation and 'servers' not in path_item,
            'OPENAPI_OPERATION_SERVER_OVERRIDE_REVIEW_REQUIRED')
    placeholders=_path(path)
    params, query, path_schema = _parameters(document, path_item, operation, placeholders)
    responses=operation.get('responses')
    _reject(type(responses) is dict and type(responses.get('200')) is dict,
            'OPENAPI_GET_200_RESPONSE_REQUIRED')
    success={code for code in responses if type(code) is str and
             (code.startswith('2') or code=='default')}
    _reject(success=={'200'},
            'OPENAPI_ADDITIONAL_SUCCESS_RESPONSE_REVIEW_REQUIRED')
    row=responses['200']
    _reject('$ref' not in row,'OPENAPI_RESPONSE_REF_UNSUPPORTED')
    content=row.get('content')
    _reject(type(content) is dict and set(content)=={'application/json'} and
            type(content['application/json']) is dict and
            type(content['application/json'].get('schema')) is dict,
            'OPENAPI_JSON_200_SCHEMA_REQUIRED')
    shaped=_Shape(document)
    result,projection=shaped.object(content['application/json']['schema'])
    source={'name':name,'description':'Imported READ '+name,
            'version':'1','route':name,'credential':None,
            'targets':[],'paramsSchema':{'type':'object','fields':params},
            'pathTargetParam':placeholders[0] if placeholders else None,
            'query':query,'resultSchema':result,'projection':projection,
            'checks':{'targetEquals':None,'unique':None,'page':None},
            'maxResultBytes':65536}
    route={'name':name,'path':path,'queryKeys':sorted(query.values())}
    return source, route, path_schema


def inspect_openapi(document,provider):
    """Pure bounded read: returns UNREVIEWED templates, never runnable source."""
    ident(provider)
    check(provider not in RESERVED,'SOURCE_PROVIDER_RESERVED')
    doc=_normalize(document)
    canonical_doc=canonical(doc)
    rows=[];routes=[];templates=[];names=set()
    methods=0
    for path in sorted(doc['paths']):
        item=doc['paths'][path]
        check(type(item) is dict,'OPENAPI_PATH_ITEM_INVALID')
        for verb in sorted(k for k in item if k.lower() in _METHODS):
            methods+=1
            check(methods<=_MAX_OPERATIONS,'OPENAPI_OPERATION_LIMIT')
            raw=item[verb]
            check(type(raw) is dict,'OPENAPI_OPERATION_INVALID')
            op_name=raw.get('operationId')
            if op_name is None:
                op_name='get_'+sha256((verb+' '+path).encode()).hexdigest()[:12]
            valid_name=type(op_name) is str and IDENT.fullmatch(op_name)
            name=op_name if valid_name else None
            if name is not None:
                check(name not in names,'OPENAPI_DUPLICATE_OPERATION_ID')
                names.add(name)
            item_status={'name':name,'verb':verb.upper(),
                         'path':path,'status':'REVIEW_REQUIRED',
                         'reasonCodes':[],'sourceMethod':None,'pathTargetSchema':None}
            if not valid_name:
                item_status['reasonCodes']=['OPENAPI_OPERATION_ID_REVIEW_REQUIRED']
            elif verb.lower()!='get':
                item_status['reasonCodes']=['OPENAPI_WRITE_OR_NON_GET_REVIEW_REQUIRED']
            elif '$ref' in item:
                item_status['reasonCodes']=['OPENAPI_PATH_ITEM_REF_REVIEW_REQUIRED']
            else:
                try:
                    description, route, path_schema = _operation(doc, path, item, name, raw)
                    templates.append(description)
                    routes.append(route)
                    item_status['status']='DRAFT_COMPILABLE'
                    item_status['sourceMethod']=deepcopy(description)
                    item_status['pathTargetSchema'] = path_schema
                except _Gap as gap:
                    item_status['reasonCodes']=[gap.code]
            item_status['nextAction']=(
                'VERIFY_RESPONSE_FIXTURES_AND_BIND_SOURCE'
                if item_status['status']=='DRAFT_COMPILABLE' else
                'REVIEW_WRITE_EFFECT_SEPARATELY' if verb.lower()!='get' else
                'REVIEW_UNSUPPORTED_GET_OR_IMPLEMENT_MANUAL_OPERATION')
            rows.append(item_status)
    check(rows,'OPENAPI_NO_HTTP_OPERATIONS')
    template={'schemaVersion':1,'provider':provider,'transport':'jsonapi',
              'origin':None,'routes':routes,'methods':templates}
    return {'schemaVersion':1,'kind':'OPENAPI_SOURCE_DRAFT',
            'specSha256':sha256(canonical_doc.encode('utf-8')).hexdigest(),
            'provider':provider,'openapiVersion':doc['openapi'],
            'status':'REVIEW_REQUIRED','reviewed':False,
            'operations':rows,'sourceTemplate':template,
            'reviewTasks':['Verify upstream identity/TLS and fixed HTTPS origin',
                           'Verify response fixtures, schemas, targets and actor/policy',
                           'Review authorization and security schemes separately',
                           'Review every excluded/unsupported method and effect',
                           'Run source/negative tests and independent PR/CI before release']}


def _check_bound_path_targets(schema, targets):
    check(type(schema) is dict and schema.get('type') in ('string', 'integer'),
          'OPENAPI_PATH_SCHEMA_REINSPECTION_REQUIRED')
    validate = _value_schema(schema, [0])
    for target in targets:
        value = target
        if schema['type'] == 'integer':
            check(target.isdecimal(), 'OPENAPI_PATH_TARGET_SCHEMA_MISMATCH')
            value = int(target)
            check(str(value) == target, 'OPENAPI_PATH_TARGET_SCHEMA_MISMATCH')
        try:
            validate(value)
        except Denied:
            raise Denied('OPENAPI_PATH_TARGET_SCHEMA_MISMATCH') from None


def bind_source_draft(plan,origin,targets_by_method,*,selected=None):
    """Review-time source candidate binding: never promotes review or grants.

    Caller must explicitly choose a subset when some methods were unsupported.
    Source compilation is tested but does NOT prove live upstream behavior.
    """
    check(type(plan) is dict and plan.get('schemaVersion')==1 and
          plan.get('kind')=='OPENAPI_SOURCE_DRAFT' and
          plan.get('reviewed') is False and
          plan.get('status')=='REVIEW_REQUIRED' and
          type(plan.get('operations')) is list and
          type(plan.get('sourceTemplate')) is dict,
          'OPENAPI_DRAFT_INVALID')
    check(type(plan.get('specSha256')) is str and
          re.fullmatch(r'[0-9a-f]{64}',plan['specSha256']) and
          type(plan['sourceTemplate'].get('provider')) is str and
          plan.get('provider')==plan['sourceTemplate']['provider'],
          'OPENAPI_DRAFT_INVALID')
    template=plan['sourceTemplate']
    check(template.get('schemaVersion')==1 and
          template.get('transport')=='jsonapi' and template.get('origin') is None and
          type(template.get('methods')) is list and
          type(template.get('routes')) is list and
          all(type(row) is dict and row.get('targets')==[] and
              row.get('credential') is None for row in template['methods']),
          'OPENAPI_DRAFT_INVALID')
    compilable = {row['name']: row for row in plan['operations']
                  if row['status'] == 'DRAFT_COMPILABLE'}
    expected = {name: row['sourceMethod'] for name, row in compilable.items()}
    safe_routes = {name: row['path'] for name, row in compilable.items()}
    check(len(expected)==len(template['methods']) and
          {row['name']:row for row in template['methods']}==expected and
          {row['name']:row['path'] for row in template['routes']}==safe_routes,
          'OPENAPI_DRAFT_INVALID')
    accepted=set(expected)
    if selected is None:
        check(all(row['status'] == 'DRAFT_COMPILABLE' for row in plan['operations']),
              'OPENAPI_EXPLICIT_METHOD_SELECTION_REQUIRED')
        selected=sorted(accepted)
    check(type(selected) is list and selected and
          all(type(x) is str for x in selected) and
          len(set(selected))==len(selected) and set(selected)<=accepted,
          'OPENAPI_SELECTION_INVALID')
    check(type(targets_by_method) is dict and
          set(targets_by_method)==set(selected),
          'OPENAPI_TARGET_BINDING_REQUIRED')
    output=deepcopy(plan['sourceTemplate'])
    output['origin']=origin
    output['routes']=[row for row in output['routes'] if row['name'] in selected]
    output['methods']=[row for row in output['methods'] if row['name'] in selected]
    for method in output['methods']:
        targets=targets_by_method[method['name']]
        check(type(targets) is list and targets and len(targets)<=100 and
              all(type(x) is str and TARGET.fullmatch(x) for x in targets) and
              len(set(targets))==len(targets),
              'OPENAPI_TARGET_BINDING_REQUIRED')
        if method['pathTargetParam'] is not None:
            _check_bound_path_targets(compilable[method['name']].get('pathTargetSchema'),
                                      targets)
        method['targets']=deepcopy(targets)
    # Full real compiler/HTTPS origin validation. Never writes source here.
    render_package(output)
    excluded = []
    for row in plan['operations']:
        unsupported = row['status'] != 'DRAFT_COMPILABLE'
        if unsupported or row['name'] not in selected:
            label = row['name'] if row['name'] is not None else row['verb'] + ' ' + row['path']
            detail = {key: row[key] for key in ('name', 'verb', 'path')}
            detail['reason'] = 'unsupported' if unsupported else 'explicitly_not_selected'
            detail['reasonCodes'] = list(row['reasonCodes'])
            excluded.append((label, detail))
    excluded.sort(key=lambda entry: entry[0])
    return {'sourceDescription':output,'specSha256':plan['specSha256'],
            'status':'REVIEW_REQUIRED','reviewed':False,
            'selectedMethods':sorted(selected),
            'excludedMethods': [label for label, _ in excluded],
            'excludedMethodDetails': [detail for _, detail in excluded],
            'nextStep':'Independent source/fixtures review; then advise_onboarding and begin with verified evidence.'}


def main():
    """Read-only local JSON intake; no URL fetching or source mutation."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec',required=True,
                        help='Local OpenAPI 3.0/3.1 JSON file only; never a URL')
    parser.add_argument('--provider',required=True)
    args=parser.parse_args()
    try:
        path=Path(args.spec)
        check(path.is_file() and not path.is_symlink(),
              'OPENAPI_LOCAL_SPEC_REQUIRED')
        check(path.stat().st_size<=_MAX_SPEC_BYTES, 'OPENAPI_DOCUMENT_TOO_LARGE')
        with path.open('rb') as reader:
            content=reader.read(_MAX_SPEC_BYTES+1)
        print(canonical(inspect_openapi(content,args.provider)))
    except (Denied,OSError,UnicodeError) as error:
        parser.exit(2,'OpenAPI draft STOP: '+
                    (str(error) if isinstance(error,Denied) else
                     'OPENAPI_LOCAL_SPEC_UNREADABLE')+'\n')


if __name__=='__main__':
    main()
