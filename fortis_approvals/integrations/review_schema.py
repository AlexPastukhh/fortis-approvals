"""Small closed-schema validators shared by typed analysis integrations."""
import re
from ..core import Denied


def require(value, code='ANALYSIS_SCHEMA_INVALID'):
    if not value:
        raise Denied(code)


def text(value, limit=4000, *, empty=True):
    require(type(value) is str and (empty or bool(value.strip())) and '\0' not in value)
    try:
        require(len(value.encode('utf-8')) <= limit)
    except UnicodeError:
        raise Denied('ANALYSIS_TEXT_INVALID') from None
    return value


def ident(value):
    text(value, 128, empty=False)
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value))
    return value


def number(value, maximum=2**63-1, minimum=1):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def sha(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{40}', value))
    return value


def boolean(value):
    require(type(value) is bool)
    return value


def nullable(check):
    def validate(value):
        return None if value is None else check(value)
    return validate


def array(check, limit=100):
    def validate(value):
        require(type(value) is list and len(value) <= limit)
        return [check(x) for x in value]
    return validate


def object_schema(fields):
    def validate(value):
        require(type(value) is dict and set(value) == set(fields))
        return {k: check(value[k]) for k, check in fields.items()}
    return validate


def project(raw, fields):
    """Select only known provider fields, then validate; never echo raw JSON."""
    require(type(raw) is dict)
    return object_schema(fields)({k: raw.get(k) for k in fields})


def context(value):
    require(type(value) is dict and len(value) <= 1)
    if 'branch' in value:
        name = text(value['branch'], 200, empty=False)
        require(not name.startswith('-') and all(ord(c) >= 32 for c in name))
    elif 'pullRequest' in value:
        require(type(value['pullRequest']) is str and re.fullmatch('[1-9][0-9]{0,9}', value['pullRequest']))
    else:
        require(not value)
    return value


def page(params, size='pageSize'):
    number(params['page'], 100)
    number(params[size], 100)


def fields(params, required, optional=()):
    require(type(params) is dict and set(required) <= set(params) <= set(required) | set(optional))

def strict_json(raw):
    """Bounded callers supply bytes/text; reject duplicates and non-finite JSON."""
    import json
    import math

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('DUPLICATE_FIELD')
            result[key] = value
        return result

    def constant(value):
        raise ValueError('NONFINITE_JSON')

    def finite(value):
        parsed = float(value)
        if not math.isfinite(parsed): raise ValueError('NONFINITE_JSON')
        return parsed

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Denied('ANALYSIS_JSON_INVALID') from None
