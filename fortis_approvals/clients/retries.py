"""Bounded retries for semantic READs; never a generic mutation retry loop."""
import re
import time


READ_POST_PATHS = frozenset({
    '/v1/reads', '/v1/workspace/capabilities', '/v1/workspace/details',
    '/v1/workspace/result', '/v1/workspace/list_requests',
    '/v1/workspace/list_uncertain', '/v1/workspace/activity', '/v1/git/fetch',
})


def seconds_header(headers, name='Retry-After'):
    try:
        value = headers.get(name)
    except (AttributeError, TypeError, ValueError):
        return None
    if type(value) is str and re.fullmatch(r'[0-9]{1,6}', value):
        number = int(value)
        if 0 < number <= 604800:
            return number
    return None


def transient(exc):
    """Use fixed public codes, not arbitrary exception text or provider bodies."""
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    code = exc.args[0] if len(exc.args) == 1 else None
    if type(code) is not str:
        return False
    if code in {
        'FORTIS_HTTP_429', 'FORTIS_HTTP_500', 'FORTIS_HTTP_502',
        'FORTIS_HTTP_503', 'FORTIS_HTTP_504',
        'FORTIS_UPSTREAM_UNAVAILABLE_OR_INVALID',
    }:
        return getattr(exc, 'retryable_transport', True)
    if re.fullmatch(r'FORTIS_READ_GITHUB_HTTP_(429|500|502|503|504)(?:_[A-Z_]+)?', code):
        return True
    if code.startswith('FORTIS_READ_GITHUB_HTTP_403_'):
        return code.endswith(('_PRIMARY_RATE_LIMIT_REPORTED', '_BACKOFF_HEADER_PRESENT'))
    if code == 'FORTIS_READ_GITHUB_UPSTREAM_UNAVAILABLE_OR_INVALID':
        return True
    if re.fullmatch(r'FORTIS_(ARTIFACT|FETCH)_GIT_(OUTCOME_TIMEOUT|NETWORK_FAILURE_REPORTED|UPSTREAM_HTTP_FAILURE)(?:_[A-Z_]+)?',code):
        return True
    if re.fullmatch(r'FORTIS_(ARTIFACT|FETCH)_GIT_RATE_LIMIT_REPORTED(?:_[A-Z_]+)?',code):
        return True
    return code in {
        'FORTIS_ARTIFACT_GIT_COMMAND_FAILED_FETCH_MAIN',
        'FORTIS_ARTIFACT_GIT_COMMAND_FAILED_READ_REMOTE_REFS',
        'FORTIS_ARTIFACT_GIT_COMMAND_FAILED_FETCH_TASK',
        'FORTIS_FETCH_GIT_COMMAND_FAILED_FETCH_MAIN',
        'FORTIS_FETCH_GIT_COMMAND_FAILED_FETCH_TASK',
    }


class RetryPolicy:
    def __init__(self, attempts=3, *, sleep=time.sleep, clock=time.time,
                 max_wait=120, base_delay=1):
        if type(attempts) is not int or not 1 <= attempts <= 3:
            raise ValueError('RETRY_ATTEMPTS_INVALID')
        self.attempts = attempts
        self.sleep, self.clock = sleep, clock
        self.max_wait, self.base_delay = max_wait, base_delay
        self.deferred = {}

    def delay(self, exc, attempt):
        delay = self.base_delay * 2 ** attempt
        hint = getattr(exc, 'retry_after_seconds', None)
        if type(hint) in (int, float) and 0 < hint <= 604800:
            delay = max(delay, hint)
        metadata = getattr(exc, 'provider_metadata', None)
        if type(metadata) is dict:
            reset = metadata.get('rateLimitReset')
            if type(reset) is int and str(exc).endswith('PRIMARY_RATE_LIMIT_REPORTED'):
                delay = max(delay, reset - self.clock() + 1)
        # A local 429 from older Gateway versions has no backoff header.
        if str(exc) == 'FORTIS_HTTP_429' and hint is None:
            delay = max(delay, 60)
        if str(exc).startswith('FORTIS_READ_GITHUB_HTTP_403_') and hint is None:
            delay = max(delay, 60)
        if str(exc).startswith('FORTIS_READ_GITHUB_HTTP_429') and hint is None:
            delay = max(delay, 60)
        if '_GIT_RATE_LIMIT_REPORTED' in str(exc) and hint is None:
            delay = max(delay, 60)
        return max(0, delay)

    def read(self, call, *, key=None):
        waited = 0
        pending = self.deferred.get(key)
        if pending is not None:
            until, previous = pending
            remaining = max(0, until - self.clock())
            if remaining > self.max_wait:
                raise previous
            if remaining:
                self.sleep(remaining); waited += remaining
        for attempt in range(self.attempts):
            try:
                value = call()
                self.deferred.pop(key, None)
                return value
            except Exception as exc:
                if not transient(exc):
                    raise
                delay = self.delay(exc, attempt)
                self.deferred[key] = (self.clock() + delay, exc)
                if attempt + 1 == self.attempts:
                    raise
                if waited + delay > self.max_wait:
                    # Preserve the real failure and its wait hint for a later call.
                    raise
                self.sleep(delay)
                waited += delay
