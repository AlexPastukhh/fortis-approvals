"""Optional analysis transport. The release-pinned legacy transport is unchanged."""
from urllib import error, parse, request

from ....core import Denied
from ...review_schema import strict_json
from ..analysis_contract import GET_ROUTES, POST_ROUTES
from .sonar import SonarHTTPTransport, SonarTransportError


class SonarAnalysisTransport(SonarHTTPTransport):
    def __init__(self, original):
        if not isinstance(original, SonarHTTPTransport):
            raise ValueError('SONAR_TRUSTED_TRANSPORT_REQUIRED')
        # All values originate in trusted Gateway provisioning; never a Repo
        # payload. Reuse the fixed-origin, proxy-free, no-redirect TLS opener.
        self._origin = original._origin
        self._token = original._token
        self._timeout = original._timeout
        self._opener = original._opener

    def call(self, method, path, params):
        routes = GET_ROUTES if method == 'GET' else POST_ROUTES if method == 'POST' else {}
        if path not in routes:
            return super().call(method, path, params)
        if (type(params) is not dict or not set(params) <= routes[path] or
                not all(type(k) is str and type(v) is str for k, v in params.items())):
            raise Denied('SONAR_ANALYSIS_HTTP_PARAMS_DENIED')
        fields = params.get('additionalFields')
        permitted_fields = {'/api/issues/search': {'transitions', 'comments,transitions'},
                            '/api/ce/task': {'warnings'},
                            '/api/measures/component': {'metrics,periods'}}
        if fields is not None and fields not in permitted_fields.get(path, set()):
            raise Denied('SONAR_ANALYSIS_FIELDS_DENIED')
        encoded = parse.urlencode(params).encode('ascii')
        url = self._origin + path + ('?' + encoded.decode('ascii') if method == 'GET' else '')
        headers = {'Authorization': 'Bearer ' + self._token, 'Accept': 'application/json'}
        if method == 'POST': headers['Content-Type'] = 'application/x-www-form-urlencoded'
        outgoing = request.Request(url, data=encoded if method == 'POST' else None,
                                   method=method, headers=headers)
        try:
            with self._opener.open(outgoing, timeout=self._timeout) as response:
                if response.status != 200: raise SonarTransportError('SONAR_HTTP_NON_200')
                content = response.read(262145)
                if len(content) > 262144: raise SonarTransportError('SONAR_RESPONSE_TOO_LARGE')
                result = strict_json(content)
                if type(result) is not dict: raise SonarTransportError('SONAR_RESPONSE_INVALID')
                return self._redact(result)
        except error.HTTPError as exc:
            status = exc.code; exc.close()
            raise SonarTransportError('SONAR_HTTP_' + str(status)) from None
        except (error.URLError, TimeoutError, OSError):
            raise SonarTransportError('SONAR_TRANSPORT_UNAVAILABLE') from None
        except (UnicodeError, ValueError, TypeError, RecursionError):
            raise SonarTransportError('SONAR_RESPONSE_INVALID') from None

    def _redact(self, value, depth=0):
        if depth > 24:
            raise SonarTransportError('SONAR_RESPONSE_NESTING_LIMIT')
        if type(value) is str:
            return value.replace(self._token, '[REDACTED]')
        if type(value) is list:
            return [self._redact(x, depth + 1) for x in value]
        if type(value) is dict:
            return {k: self._redact(v, depth + 1) for k, v in value.items()}
        return value
