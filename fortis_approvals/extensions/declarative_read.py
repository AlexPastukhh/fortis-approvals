"""Source-owned declarative READ operations for existing trusted transports.

No runtime descriptor import or arbitrary URL/credential/policy/route from callers.
Compiled definitions are image-owned Python source subject to normal CI/release.
WRITE, unreviewed OpenAPI import and dynamic provider installation are excluded.
"""
from copy import deepcopy
import re

from ..core import Denied, canonical
from .model import Operation, Provider, TARGET, bounded, check, ident, forbid_credentials

_FIELD = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
_ASCII = re.compile(r'[A-Za-z0-9-]+\Z')
_SLUG = re.compile(r'[a-z][a-z0-9_-]*\Z')
_HEX = re.compile(r'[a-f0-9]+\Z')
_SCHEMA_NODE_LIMIT = 128
_MAX_DEPTH = 8


def _keys(value, keys, code='DECLARATIVE_DEFINITION_INVALID'):
    check(type(value) is dict and set(value) == set(keys), code)


def _size(value, maximum=65536):
    bounded(value, maximum)


def _value_schema(spec, budget, depth=0):
    """Compile a fixed, bounded shape grammar to a validator. No dynamic eval."""
    check(type(spec) is dict and depth <= _MAX_DEPTH, 'DECLARATIVE_SCHEMA_INVALID')
    budget[0] += 1
    check(budget[0] <= _SCHEMA_NODE_LIMIT, 'DECLARATIVE_SCHEMA_COMPLEXITY')
    kind = spec.get('type')
    if kind == 'object':
        _keys(spec, ('type', 'fields'))
        fields = spec['fields']
        check(type(fields) is dict and 0 <= len(fields) <= 25 and
              all(type(k) is str and _FIELD.fullmatch(k) for k in fields),
              'DECLARATIVE_SCHEMA_FIELDS')
        compiled = {k: _value_schema(s, budget, depth + 1) for k, s in fields.items()}

        def validate(value):
            check(type(value) is dict and set(value) == set(compiled),
                  'DECLARATIVE_OBJECT_INVALID')
            for key, fn in compiled.items():
                fn(value[key])
    elif kind == 'array':
        _keys(spec, ('type', 'items', 'maxItems'))
        maximum = spec['maxItems']
        check(type(maximum) is int and 0 <= maximum <= 256, 'DECLARATIVE_ARRAY_LIMIT')
        item = _value_schema(spec['items'], budget, depth + 1)

        def validate(value):
            check(type(value) is list and len(value) <= maximum,
                  'DECLARATIVE_ARRAY_INVALID')
            for row in value:
                item(row)
    elif kind == 'nullable':
        _keys(spec, ('type', 'item'))
        fn = _value_schema(spec['item'], budget, depth + 1)

        def validate(value):
            if value is not None:
                fn(value)
    elif kind == 'string':
        _keys(spec, ('type', 'minLength', 'maxLength', 'unit', 'printable', 'format'))
        minimum, maximum = spec['minLength'], spec['maxLength']
        unit, printable, fmt = spec['unit'], spec['printable'], spec['format']
        check(type(minimum) is int and type(maximum) is int and
              0 <= minimum <= maximum <= 65536 and
              unit in ('codepoints', 'utf8bytes') and type(printable) is bool,
              'DECLARATIVE_STRING_DEFINITION')
        if fmt is not None:
            check(type(fmt) is dict and type(fmt.get('kind')) is str,
                  'DECLARATIVE_FORMAT_DEFINITION')
            if fmt['kind'] in ('lowerSlug', 'alnumDash'):
                _keys(fmt, ('kind',))
            elif fmt['kind'] == 'prefixLowerHex':
                _keys(fmt, ('kind', 'prefix', 'digits'))
                check(type(fmt['prefix']) is str and
                      1 <= len(fmt['prefix']) <= 16 and
                      re.fullmatch(r'[a-z0-9_]+', fmt['prefix']) is not None and
                      type(fmt['digits']) is int and 1 <= fmt['digits'] <= 64,
                      'DECLARATIVE_FORMAT_DEFINITION')
            else:
                raise Denied('DECLARATIVE_FORMAT_UNSUPPORTED')

        def validate(value):
            check(type(value) is str, 'DECLARATIVE_STRING_INVALID')
            try:
                measured = len(value) if unit == 'codepoints' else len(value.encode('utf-8'))
            except UnicodeError:
                raise Denied('DECLARATIVE_STRING_INVALID') from None
            check(minimum <= measured <= maximum and
                  (not printable or all(ord(c) >= 32 for c in value)),
                  'DECLARATIVE_STRING_INVALID')
            if fmt is not None:
                if fmt['kind'] == 'lowerSlug':
                    matched = _SLUG.fullmatch(value) is not None
                elif fmt['kind'] == 'alnumDash':
                    matched = _ASCII.fullmatch(value) is not None
                else:
                    prefix, digits = fmt['prefix'], fmt['digits']
                    suffix = value[len(prefix):]
                    matched = (value.startswith(prefix) and len(suffix) == digits and
                               _HEX.fullmatch(suffix) is not None)
                check(matched, 'DECLARATIVE_STRING_FORMAT')
    elif kind == 'integer':
        _keys(spec, ('type', 'minimum', 'maximum', 'choices'))
        lo, hi, choices = spec['minimum'], spec['maximum'], spec['choices']
        check((lo is None or type(lo) is int) and (hi is None or type(hi) is int) and
              (lo is None or hi is None or lo <= hi) and
              (choices is None or (type(choices) is list and 0 < len(choices) <= 100 and
                                   all(type(x) is int for x in choices) and
                                   len(set(choices)) == len(choices))),
              'DECLARATIVE_INTEGER_DEFINITION')

        def validate(value):
            check(type(value) is int and (lo is None or value >= lo) and
                  (hi is None or value <= hi) and
                  (choices is None or value in choices),
                  'DECLARATIVE_INTEGER_INVALID')
    elif kind == 'boolean':
        _keys(spec, ('type', 'equals'))
        expected = spec['equals']
        check(expected is None or type(expected) is bool, 'DECLARATIVE_BOOL_DEFINITION')

        def validate(value):
            check(type(value) is bool and (expected is None or value is expected),
                  'DECLARATIVE_BOOL_INVALID')
    elif kind == 'literal':
        _keys(spec, ('type', 'equals'))
        expected = spec['equals']
        check(type(expected) in (str, int, bool) and
              (type(expected) is not str or 0 < len(expected) <= 256),
              'DECLARATIVE_LITERAL_DEFINITION')

        def validate(value):
            check(type(value) is type(expected) and value == expected,
                  'DECLARATIVE_LITERAL_INVALID')
    else:
        raise Denied('DECLARATIVE_SCHEMA_TYPE_UNSUPPORTED')
    return validate


def _projection_compile(rule, depth=0):
    check(type(rule) is dict and depth <= 4 and 0 < len(rule) <= 25,
          'DECLARATIVE_PROJECTION_INVALID')
    projected = {}
    for dest, source in rule.items():
        check(type(dest) is str and _FIELD.fullmatch(dest),
              'DECLARATIVE_PROJECTION_INVALID')
        if type(source) is str:
            check(_FIELD.fullmatch(source), 'DECLARATIVE_PROJECTION_INVALID')
            projected[dest] = source
        else:
            _keys(source, ('array', 'fields'), 'DECLARATIVE_PROJECTION_INVALID')
            check(type(source['array']) is str and _FIELD.fullmatch(source['array']),
                  'DECLARATIVE_PROJECTION_INVALID')
            projected[dest] = (source['array'], _projection_compile(source['fields'],depth+1))
    return projected


def _project(raw, projection):
    check(type(raw) is dict, 'DECLARATIVE_UPSTREAM_OBJECT')
    value = {}
    for dest, source in projection.items():
        if type(source) is str:
            check(source in raw, 'DECLARATIVE_UPSTREAM_FIELD_MISSING')
            value[dest] = raw[source]
        else:
            name, children = source
            check(name in raw and type(raw[name]) is list and len(raw[name]) <= 256,
                  'DECLARATIVE_UPSTREAM_ARRAY_INVALID')
            value[dest] = [_project(item,children) for item in raw[name]]
    return value


def _checks_compile(checks, result_schema, params_schema, targets):
    _keys(checks, ('targetEquals', 'unique', 'page'))
    output = result_schema['fields']
    target = checks['targetEquals']
    if target is not None:
        _keys(target, ('field', 'coerce'))
        check(target['field'] in output and target['coerce'] in ('none', 'decimal'),
              'DECLARATIVE_IDENTITY_CHECK')
        field_spec = output[target['field']]
        if target['coerce'] == 'decimal':
            check(field_spec['type'] == 'integer', 'DECLARATIVE_IDENTITY_CHECK')
            check(all(re.fullmatch(r'(?:0|[1-9][0-9]*)', t) for t in targets),
                  'DECLARATIVE_DECIMAL_TARGET_INVALID')
            numbers = [int(t) for t in targets]
            check(all((field_spec['minimum'] is None or x >= field_spec['minimum']) and
                      (field_spec['maximum'] is None or x <= field_spec['maximum']) and
                      (field_spec['choices'] is None or x in field_spec['choices'])
                      for x in numbers), 'DECLARATIVE_DECIMAL_TARGET_INVALID')
        else:
            check(field_spec['type'] in ('string', 'literal'),
                  'DECLARATIVE_IDENTITY_CHECK')
    unique = checks['unique']
    if unique is not None:
        _keys(unique, ('array', 'field'))
        check(unique['array'] in output and output[unique['array']]['type']=='array' and
              output[unique['array']]['items']['type']=='object' and
              unique['field'] in output[unique['array']]['items']['fields'],
              'DECLARATIVE_UNIQUE_CHECK')
        key_spec = output[unique['array']]['items']['fields'][unique['field']]
        while key_spec.get('type') == 'nullable':
            key_spec = key_spec['item']
        check(key_spec['type'] in ('string', 'integer', 'boolean', 'literal'),
              'DECLARATIVE_UNIQUE_KEY_UNSUPPORTED')
    page = checks['page']
    if page is not None:
        _keys(page, ('items', 'nextOffset', 'revision', 'offsetParam', 'limitParam', 'revisionParam'))
        check(all(type(page[k]) is str for k in page), 'DECLARATIVE_PAGE_CHECK')
        result_fields = output
        params_fields = params_schema['fields']
        check(page['items'] in result_fields and page['nextOffset'] in result_fields and
              page['revision'] in result_fields and
              all(page[k] in params_fields for k in
                  ('offsetParam', 'limitParam', 'revisionParam')),
              'DECLARATIVE_PAGE_CHECK')
        items_spec = result_fields[page['items']]
        next_spec = result_fields[page['nextOffset']]
        revision_spec = result_fields[page['revision']]
        offset_spec = params_fields[page['offsetParam']]
        limit_spec = params_fields[page['limitParam']]
        revision_param = params_fields[page['revisionParam']]
        check(items_spec['type']=='array' and
              offset_spec['type']=='integer' and offset_spec['minimum'] is not None and
              offset_spec['minimum']>=0 and
              limit_spec['type']=='integer' and limit_spec['minimum'] is not None and
              limit_spec['minimum']>=1 and
              limit_spec['maximum'] is not None and
              limit_spec['maximum']<=items_spec['maxItems'] and
              next_spec['type']=='nullable' and next_spec['item']['type']=='integer' and
              next_spec['item']['minimum'] is not None and
              next_spec['item']['minimum']>=0 and
              revision_spec['type']=='string' and
              revision_param['type']=='nullable' and
              revision_param['item']['type']=='string',
              'DECLARATIVE_PAGE_TYPES_INVALID')
    return deepcopy(checks)


def compile_read_provider(service, api, specs, *, postchecks=None, context_checks=None):
    """Generate immutable source-owned Operation callables for reviewed API routes.

    `api` and hooks are trusted code objects, never user-selected values.
    postchecks(value) are rechecked by Operation.result and during execution.
    context_checks(target, params, value) are execution-only and may not be
    relied on for receipt/result validation without stored request context.
    The caller must supply only an image-owned, source-reviewed definition.
    """
    ident(service)
    check(type(specs) is tuple and 1 <= len(specs) <= 100,
          'DECLARATIVE_METHOD_COUNT')
    check(api is not None and type(api.routes) is dict,
          'DECLARATIVE_API_REQUIRED')
    postchecks = {} if postchecks is None else postchecks
    context_checks = {} if context_checks is None else context_checks
    check(all(type(hooks) is dict and all(type(k) is str and callable(v)
          for k, v in hooks.items()) for hooks in (postchecks, context_checks)),
          'DECLARATIVE_HOOK_INVALID')
    result = []
    names = set()
    for candidate in specs:
        _keys(candidate, ('name','description','version','route','credential','targets',
                          'paramsSchema','pathTargetParam','query','resultSchema',
                          'projection','checks','maxResultBytes'))
        spec = deepcopy(candidate)
        name = ident(spec['name'])
        check(name not in names,'DECLARATIVE_DUPLICATE_METHOD');names.add(name)
        route = ident(spec['route'])
        check(route in api.routes,'DECLARATIVE_ROUTE_NOT_REGISTERED')
        definition = api.routes[route]
        check(definition.method=='GET' and definition.readonly,
              'DECLARATIVE_READ_ONLY_REQUIRED')
        targets=spec['targets']
        check(type(targets) is list and 1 <= len(targets) <= 100 and
              len(set(targets))==len(targets) and all(type(t) is str and
              TARGET.fullmatch(t) for t in targets), 'DECLARATIVE_TARGET_SCOPE')
        # Only target-bound upstream paths. No arbitrary param or URL as path.
        path=spec['pathTargetParam']
        check(path is None or type(path) is str and _FIELD.fullmatch(path),
              'DECLARATIVE_PATH_BINDING')
        placeholders=re.findall(r'\{([a-z][a-z0-9_]*)\}',definition.path)
        check(placeholders==([] if path is None else [path]),
              'DECLARATIVE_PATH_BINDING')
        query=spec['query']
        params_schema=spec['paramsSchema']
        result_schema=spec['resultSchema']
        check(type(params_schema) is dict and params_schema.get('type')=='object' and
              type(result_schema) is dict and result_schema.get('type')=='object',
              'DECLARATIVE_OBJECT_SCHEMAS_REQUIRED')
        # Validate both schemas before inspecting any members: broken source
        # must fail as a controlled definition error, not a raw KeyError.
        param_validate = _value_schema(params_schema,[0])
        result_validate = _value_schema(result_schema,[0])
        # Reuse the trusted credential-key policy for caller input fields.
        try:
            forbid_credentials({name: None for name in params_schema['fields']})
        except Denied:
            raise Denied('DECLARATIVE_CREDENTIAL_PARAM_DENIED') from None
        check(type(query) is dict and set(query)<=set(params_schema['fields']) and
              all(type(k) is str and _FIELD.fullmatch(k) and type(v) is str and
                  v in definition.query_keys for k,v in query.items()) and
              len(set(query.values()))==len(query), 'DECLARATIVE_QUERY_MAPPING')
        # Reject ignored caller params: a method must use every public param.
        check(set(query)==set(params_schema['fields']), 'DECLARATIVE_UNUSED_PARAM')
        projection=spec['projection']
        compiled_projection=(None if projection is None else
                             _projection_compile(projection))
        check(compiled_projection is None or
              set(compiled_projection)==set(result_schema['fields']),
              'DECLARATIVE_PROJECTION_FIELDS')
        checks=_checks_compile(spec['checks'],result_schema,params_schema,targets)
        max_bytes=spec['maxResultBytes']
        check(type(max_bytes) is int and 1024<=max_bytes<=65536,
              'DECLARATIVE_RESULT_MAX')
        result_hook=postchecks.get(name)
        context_hook=context_checks.get(name)
        description=spec['description'];version=spec['version'];credential=spec['credential']
        check(type(description) is str and description and
              type(version) is str and version and
              (credential is None or type(credential) is str),
              'DECLARATIVE_OPERATION_METADATA')

        def params(value, fn=param_validate):
            fn(value)

        def validated(value, fn=result_validate, maximum=max_bytes,
                      hook=result_hook, unique=checks['unique']):
            fn(value)
            _size(value,maximum)
            forbid_credentials(value)
            if unique is not None:
                keys=[row[unique['field']] for row in value[unique['array']]]
                check(len(set(keys))==len(keys), 'DECLARATIVE_DUPLICATE_ROW')
            if hook is not None:
                before=canonical(value)
                offered=deepcopy(value)
                check(hook(offered) is None, 'DECLARATIVE_HOOK_RETURN_INVALID')
                check(before==canonical(offered), 'DECLARATIVE_HOOK_MUTATED_RESULT')

        def execute(ctx, allowed=frozenset(targets), path=path, query=dict(query),
                    route=route, params_fn=param_validate, result_fn=validated,
                    projection=compiled_projection, checks=checks, hook=context_hook):
            check(type(ctx.target) is str and ctx.target in allowed,
                  'DECLARATIVE_TARGET_DENIED')
            params_fn(ctx.params)
            kwargs = {}
            if path is not None:
                kwargs['path']={path:ctx.target}
            if query:
                kwargs['query']={remote:ctx.params[local] for local,remote in query.items()
                                 if ctx.params[local] is not None}
            page=checks['page']
            if page is not None:
                check(ctx.params[page['offsetParam']]==0 or
                      ctx.params[page['revisionParam']] is not None,
                      'DECLARATIVE_REVISION_REQUIRED')
            raw=ctx.call(route,**kwargs)
            value=raw if projection is None else _project(raw,projection)
            result_fn(value)
            identity=checks['targetEquals']
            if identity is not None:
                expected=(int(ctx.target) if identity['coerce']=='decimal' else ctx.target)
                check(value[identity['field']]==expected,
                      'DECLARATIVE_TARGET_MISMATCH')
            if page is not None:
                offset=ctx.params[page['offsetParam']]
                limit=ctx.params[page['limitParam']]
                revision=ctx.params[page['revisionParam']]
                rows=value[page['items']]
                check(len(rows)<=limit and
                      (revision is None or value[page['revision']]==revision),
                      'DECLARATIVE_PAGE_MISMATCH')
                next_offset=value[page['nextOffset']]
                check(next_offset is None or
                      (next_offset==offset+limit and len(rows)==limit),
                      'DECLARATIVE_NEXT_OFFSET_MISMATCH')
            if hook is not None:
                original=canonical(value)
                offered=deepcopy(value)
                check(hook(ctx.target,deepcopy(ctx.params),offered) is None,
                      'DECLARATIVE_HOOK_RETURN_INVALID')
                check(original==canonical(offered), 'DECLARATIVE_HOOK_MUTATED_RESULT')
            return value

        result.append(Operation(name,description,'read',params,validated,execute,
                                credential=credential,routes=(route,),version=version,
                                allowed_targets=tuple(targets)))
    check(set(postchecks)<=names and set(context_checks)<=names,
          'DECLARATIVE_HOOK_METHOD_MISSING')
    return Provider(service,tuple(result),api=api)
