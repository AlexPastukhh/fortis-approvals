"""Strict, provider-message-free codes for GitHub READ failure envelopes.

Only the server-owned fixed code travels from Gateway to Repo. HTTP status 403
alone cannot prove token permission denial, a rate limit or any other cause.
"""
import re

# Diagnostic classes come exclusively from the pinned transport's allowlisted
# request, never from an arbitrary upstream URL/header/body.
READ_ROUTE_CLASSES=frozenset({
    'ACCOUNT_REPOSITORIES','REPOSITORY_METADATA','BRANCHES','COMMITS',
    'PULL_REQUESTS','ISSUES','LABELS','ACTIONS','CHECKS','RULES','OTHER_READ',
})
READ_METHOD_CLASSES=frozenset({'READ'})
PROVIDER_METHOD_CLASSES=frozenset({'READ','WRITE'})
WRITE_ROUTE_CLASSES=frozenset({'OTHER_WRITE'}) | READ_ROUTE_CLASSES
PROVIDER_ROUTE_CLASS_HEADER='X-Fortis-GitHub-Route-Class'
PROVIDER_METHOD_CLASS_HEADER='X-Fortis-GitHub-Method-Class'
PROVIDER_RATE_RESET_HEADER='X-Fortis-GitHub-RateLimit-Reset'

def bounded_rate_limit_reset(status,headers):
    # Unix UTC seconds, NOT a clock-independent proof of throttling. Do not
    # forward arbitrary GitHub headers, dates, floats or excessively large ints.
    if type(status) is not int or status not in (403,429):
        return None
    raw=_bounded_header(headers,'X-RateLimit-Reset')
    if raw is None or re.fullmatch(r'[0-9]{9,10}',raw) is None:
        return None
    value=int(raw)
    return value if 946684800 <= value <= 4102444800 else None

def safe_read_route_class(method,path):
    if method!='GET' or type(path) is not str:
        return None
    if path=='/user/repos':
        return 'ACCOUNT_REPOSITORIES'
    # Called only after the pinned transport's own _route_allowed() has
    # already matched the full trusted path; never expose raw identifiers.
    parts=path.split('/',4)
    if len(parts)<4 or parts[1]!='repos':
        return None
    if len(parts)==4:
        return 'REPOSITORY_METADATA'
    suffix=parts[4]
    if (suffix.startswith('check-runs') or
            suffix.endswith(('/check-runs','/status'))):
        return 'CHECKS'
    if suffix.startswith(('branches','git/ref/heads/')):
        return 'BRANCHES'
    if suffix.startswith(('commits','git/commits/','compare/')):
        return 'COMMITS'
    if suffix.startswith('pulls'):
        return 'PULL_REQUESTS'
    if suffix.startswith('labels') or '/labels' in suffix:
        return 'LABELS'
    if suffix.startswith('issues'):
        return 'ISSUES'
    if suffix.startswith(('actions/','actions')):
        return 'ACTIONS'
    if suffix.startswith(('check-runs','check-')):
        return 'CHECKS'
    if suffix.startswith('rules/'):
        return 'RULES'
    return 'OTHER_READ'

def safe_write_route_class(method,path):
    # Called solely for an already allowlisted fixed provider WRITE route.
    # The classification never contains owner, repo, path, PR number or URL.
    if method not in ('POST','PATCH','PUT','DELETE') or type(path) is not str:
        return None
    parts=path.split('/',4)
    if len(parts)!=5 or parts[1]!='repos':
        return None
    suffix=parts[4]
    if suffix.startswith('pulls'):
        return 'PULL_REQUESTS'
    if suffix.startswith('issues'):
        return 'ISSUES'
    if suffix.startswith('labels') or '/labels' in suffix:
        return 'LABELS'
    if suffix.startswith('actions/'):
        return 'ACTIONS'
    if suffix.startswith('git/refs/heads/'):
        return 'BRANCHES'
    if suffix.startswith('git/'):
        return 'COMMITS'
    return 'OTHER_WRITE'  # fixed provider class, not a READ route

def bounded_transport_read_metadata(exc,provider_code):
    # Server-selected typed evidence only, never a permission/effect verdict.
    if type(provider_code) is not str or not provider_code.startswith('GITHUB_'):
        return None
    route=getattr(exc,'route_class',None)
    method=getattr(exc,'method_class',None)
    reset=getattr(exc,'rate_limit_reset',None)
    if type(route) is not str or route not in READ_ROUTE_CLASSES or method!='READ':
        return None
    result={'routeClass':route,'methodClass':'READ'}
    if (provider_code in ('GITHUB_HTTP_403','GITHUB_HTTP_429') and
            type(reset) is int and 946684800<=reset<=4102444800):
        result['rateLimitReset']=reset
    return result


# Evidence only: never infer missing credentials or an effect verdict from 403.
READ_FAILURE_SIGNALS=frozenset({
    'PRIMARY_RATE_LIMIT_REPORTED',
    'BACKOFF_HEADER_PRESENT',
    'PERMISSION_REQUIREMENTS_ADVERTISED',
})
_PERMISSION_HEADER_RE=re.compile(
    r'[A-Za-z_]{1,40}=(?:read|write|admin)(?:,[A-Za-z_]{1,40}=(?:read|write|admin))*'
    r'(?:; *[A-Za-z_]{1,40}=(?:read|write|admin)'
    r'(?:,[A-Za-z_]{1,40}=(?:read|write|admin))*)*'
)

def _bounded_header(headers, name):
    # HTTPMessage is case-insensitive; a plain dict is used by offline tests.
    try:
        getter=headers.get
        value=getter(name)
        if value is None:value=getter(name.lower())
        if value is None:value=getter(name.title())
    except (AttributeError,TypeError,ValueError):
        return None
    return value.strip() if type(value) is str and len(value)<=256 and value.isascii() and value.isprintable() else None

def classify_read_http_signal(status, headers):
    """Closed evidence class from GitHub HTTP status and bounded header syntax.

    Never copy header values, infer that a 403 was a permission denial or
    treat a backoff hint as authorization for a WRITE retry.
    """
    if type(status) is not int or status not in (401,403,404,429):
        return None
    if status in (403,429):
        if _bounded_header(headers,'X-RateLimit-Remaining')=='0':
            return 'PRIMARY_RATE_LIMIT_REPORTED'
        delay=_bounded_header(headers,'Retry-After')
        if delay and re.fullmatch(r'[0-9]{1,7}',delay) and 0<int(delay)<=604800:
            return 'BACKOFF_HEADER_PRESENT'
    if status in (401,403,404):
        requirement=_bounded_header(headers,'X-Accepted-GitHub-Permissions')
        if requirement and _PERMISSION_HEADER_RE.fullmatch(requirement):
            return 'PERMISSION_REQUIREMENTS_ADVERTISED'
    return None

def valid_read_failure_signal(provider_code, signal):
    if type(provider_code) is not str or type(signal) is not str or signal not in READ_FAILURE_SIGNALS:
        return False
    if signal in ('PRIMARY_RATE_LIMIT_REPORTED','BACKOFF_HEADER_PRESENT'):
        return provider_code in ('GITHUB_HTTP_403','GITHUB_HTTP_429')
    return provider_code in ('GITHUB_HTTP_401','GITHUB_HTTP_403','GITHUB_HTTP_404')

READ_FAILURE_CODES=frozenset({
    'GITHUB_HTTP_400','GITHUB_HTTP_401','GITHUB_HTTP_403','GITHUB_HTTP_404',
    'GITHUB_HTTP_409','GITHUB_HTTP_422','GITHUB_HTTP_429','GITHUB_HTTP_500',
    'GITHUB_HTTP_502','GITHUB_HTTP_503','GITHUB_HTTP_504',
    'GITHUB_REDIRECT_DENIED','GITHUB_HTTP_UNEXPECTED_STATUS',
    'GITHUB_RESPONSE_INVALID','GITHUB_RESPONSE_TOO_LARGE',
    'GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID','GITHUB_TRANSPORT_ERROR',
})

def bounded_read_failure_code(exc):
    """Never emit raw exception strings, provider bodies, headers or tokens."""
    code=exc.args[0] if len(exc.args)==1 else None
    return code if type(code) is str and code in READ_FAILURE_CODES else 'GITHUB_TRANSPORT_ERROR'
