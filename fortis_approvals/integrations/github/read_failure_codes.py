"""Strict, provider-message-free codes for GitHub READ failure envelopes.

Only the server-owned fixed code travels from Gateway to Repo. HTTP status 403
alone cannot prove token permission denial, a rate limit or any other cause.
"""
import re

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
