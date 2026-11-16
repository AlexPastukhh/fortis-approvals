"""Explicit config + shared Core for all extension ALLOW/ASK calls, including reads."""
from copy import deepcopy
import hashlib
from pathlib import Path

from ..core import Conflict, Denied, Stale, canonical, loads_strict
from .vault import CredentialVault, name as credential_name
from .model import Provider, TARGET, bounded, check, discover, forbid_credentials


def validate_with(callback, value, *, limit=65536):
    bounded(value, limit)
    try:
        callback(deepcopy(value))
    except Exception:
        raise Denied('INTEGRATION_SCHEMA_INVALID') from None
    return deepcopy(value)


class ExtensionConfig:
    def __init__(self, value):
        check(type(value) is dict and set(value) == {'schemaVersion', 'providers'} and
              type(value['schemaVersion']) is int and value['schemaVersion'] == 1,
              'INTEGRATION_CONFIG_INVALID')
        providers = value['providers']
        check(type(providers) is dict and 0 <= len(providers) <= 50, 'INTEGRATION_CONFIG_INVALID')
        self.value = deepcopy(value)

    @classmethod
    def from_environment(cls, env):
        raw = env.get('FORTIS_EXTENSIONS_CONFIG')
        if raw is None: return None
        check(type(raw) is str and 1 <= len(raw.encode()) <= 65536, 'INTEGRATION_CONFIG_LIMIT')
        try: return cls(loads_strict(raw))
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise Denied('INTEGRATION_CONFIG_INVALID') from None


class Context:
    """Only named, source-owned routes. Read previews never contact the provider."""
    def __init__(self, runtime, provider, operation, request, phase, *, authenticated_actor=None):
        self.runtime, self.provider, self.operation = runtime, provider, operation
        self.target, self.params = request['target'], deepcopy(request['params'])
        self.request_id, self.phase = request['requestId'], phase
        # Set only by trusted Core submission or by its persisted request row.
        # A public params/URL actor is never identity evidence.
        self.authenticated_actor = authenticated_actor
        self._secret = None
        if operation.credential:
            alias = runtime.credentials[provider.name][operation.credential]
            try: self._secret = runtime.vault.get(alias)
            except (OSError, Denied): raise Denied('INTEGRATION_CREDENTIAL_NOT_READY') from None

    @property
    def generation(self):
        return None if self._secret is None else self._secret.generation

    def safe(self, value):
        bounded(value)
        forbid_credentials(value)
        if self._secret is not None:
            # Compare decoded strings: JSON escaping must not hide quotes, slashes
            # or Unicode in a credential accidentally returned by an SDK.
            token = self._secret.reveal()
            def contains(item):
                if type(item) is str: return token in item
                if type(item) is dict: return any(contains(k) or contains(v) for k, v in item.items())
                if type(item) is list: return any(contains(v) for v in item)
                return False
            check(not contains(value), 'INTEGRATION_SECRET_OUTPUT_DENIED')
        return deepcopy(value)

    def call(self, route, *, path=None, query=None, body=None):
        check(route in self.operation.routes, 'INTEGRATION_ROUTE_DENIED')
        definition = self.provider.api.routes[route]
        if self.phase == 'preview' and self.operation.kind == 'read':
            raise Denied('INTEGRATION_READ_BEFORE_APPROVAL_DENIED')
        if self.phase != 'execute' or self.operation.kind == 'read':
            check(definition.readonly, 'INTEGRATION_PREVIEW_OR_RECONCILE_WRITE_DENIED')
        return self.provider.api.call(route, credential=self._secret, path=path, query=query,
                                      body=body, request_id=self.request_id)


class ExtensionAdapter:
    def __init__(self, runtime, provider):
        self.runtime, self.provider = runtime, provider

    def operation(self, request):
        check(request['service'] == self.provider.name, 'INTEGRATION_SERVICE_DENIED')
        return self.runtime.operations[(self.provider.name, request['operation'])]

    def prepare(self, request):
        # Backward-compatible direct adapter tests have no trusted actor.
        return self._prepare(request, authenticated_actor=None)

    def prepare_authenticated(self, request, actor):
        # Core.client authenticated actor before submit; Core.execute supplies
        # the immutable persisted row actor. Never extract identity from params.
        check(type(actor) is str and actor, 'INTEGRATION_PRINCIPAL_UNAVAILABLE')
        return self._prepare(request, authenticated_actor=actor)

    def _prepare(self, request, *, authenticated_actor):
        op = self.operation(request)
        check(request['expectedVersion'] == 0, 'INTEGRATION_VERSION_DENIED')
        validate_with(op.params, request['params'], limit=32768)
        ctx = Context(self.runtime, self.provider, op, request, 'preview',
                      authenticated_actor=authenticated_actor)
        ctx.safe(request['params'])
        try:
            preview = {} if op.preview is None else op.preview(ctx)
        except Exception:
            raise Denied('INTEGRATION_PREVIEW_FAILED') from None
        if op.preview_result is not None: validate_with(op.preview_result, preview)
        return ctx.safe({'summary': op.description, 'effect': op.kind, 'target': request['target'],
            'params': request['params'], 'before': preview, 'credentialGeneration': ctx.generation,
            'definitionDigest': self.runtime.digest})

    def apply(self, request):
        op = self.operation(request)
        row = self.runtime.core._read(request['requestId'])
        check(row['state'] == 'DISPATCHED' and row['request'] == request,
              'INTEGRATION_CORE_IDENTITY_INVALID')
        ctx = Context(self.runtime, self.provider, op, request, 'execute',
                      authenticated_actor=row['actor'])
        # Recheck frozen domain inputs and credential generation at the effect boundary.
        if canonical(self.prepare_authenticated(request, row['actor'])) != canonical(row['preview']):
            raise Stale('INTEGRATION_PREVIEW_CHANGED')
        check(ctx.generation == row['preview']['credentialGeneration'], 'INTEGRATION_CREDENTIAL_CHANGED')
        try: data = op.execute(ctx)
        except Exception: raise Denied('INTEGRATION_EXECUTION_UNCONFIRMED') from None
        validate_with(op.result, data)
        return ctx.safe({'operation': op.name, 'data': data})

    def confirm(self, request_id, result):
        row = self.runtime.core._read(request_id)
        op = self.operation(row['request'])
        check(type(result) is dict and set(result) == {'operation', 'data'} and result['operation'] == op.name,
              'INTEGRATION_RESULT_INVALID')
        validate_with(op.result, result['data'])
        return True

    def receipt(self, request_id):
        row = self.runtime.core._read(request_id); request = row['request']; op = self.operation(request)
        if op.lookup is None: return None
        ctx = Context(self.runtime, self.provider, op, request, 'reconcile')
        try: data = op.lookup(ctx)
        except Exception: raise Denied('INTEGRATION_RECONCILE_FAILED') from None
        if data is None: return None
        validate_with(op.result, data)
        return ctx.safe({'operation': op.name, 'data': data})


class ExtensionRuntime:
    def __init__(self, config, *, providers, actors, default_actor, vault=None):
        check(isinstance(config, ExtensionConfig))
        check(type(providers) is tuple and all(isinstance(x, Provider) for x in providers))
        check(len({x.name for x in providers}) == len(providers), 'INTEGRATION_DUPLICATE_PROVIDER')
        self.providers = {x.name: x for x in providers}
        self.operations = {(p.name, o.name): o for p in providers for o in p.operations}
        self.vault = vault or CredentialVault()
        self.credentials, self.rules = {}, {}
        check(default_actor in actors, 'INTEGRATION_ACTOR_INVALID')
        for service, settings in config.value['providers'].items():
            check(service in self.providers, 'INTEGRATION_PROVIDER_NOT_PACKAGED')
            check(type(settings) is dict and set(settings) == {'credentials', 'operations'}, 'INTEGRATION_CONFIG_INVALID')
            credentials, operations = settings['credentials'], settings['operations']
            known_credentials = {x.credential for x in self.providers[service].operations if x.credential}
            check(type(credentials) is dict and set(credentials) <= known_credentials, 'INTEGRATION_CREDENTIAL_BINDING_INVALID')
            for alias in credentials.values(): credential_name(alias)
            self.credentials[service] = dict(credentials)
            check(type(operations) is dict and 1 <= len(operations) <= 100, 'INTEGRATION_CONFIG_INVALID')
            for operation, rule in operations.items():
                check((service, operation) in self.operations, 'INTEGRATION_OPERATION_NOT_PACKAGED')
                op = self.operations[(service, operation)]
                check(type(rule) is dict and {'policy', 'targets'} <= set(rule) <= {'policy', 'targets', 'actors'}, 'INTEGRATION_CONFIG_INVALID')
                check(rule['policy'] in ('ALLOW', 'ASK', 'DENY'), 'INTEGRATION_POLICY_INVALID')
                targets, principals = rule['targets'], rule.get('actors', [default_actor])
                check(type(targets) is list and 1 <= len(targets) <= 100 and
                      all(type(x) is str and TARGET.fullmatch(x) for x in targets) and len(set(targets)) == len(targets), 'INTEGRATION_TARGETS_INVALID')
                check(type(principals) is list and principals and all(type(x) is str for x in principals) and set(principals) <= set(actors) and
                      len(set(principals)) == len(principals), 'INTEGRATION_ACTOR_INVALID')
                if rule['policy'] != 'DENY':
                    check(op.ready, 'INTEGRATION_HANDLER_NOT_READY')
                    check(not op.credential or op.credential in credentials, 'INTEGRATION_CREDENTIAL_BINDING_MISSING')
                for actor in principals:
                    for target in targets: self.rules[(actor, service, operation, target)] = rule['policy']
        framework = hashlib.sha256()
        for path in sorted(Path(__file__).parent.glob('*.py')):
            framework.update(path.name.encode()); framework.update(path.read_bytes())
        self.digest = hashlib.sha256(canonical({'config': config.value, 'code': framework.hexdigest(),
            'providers': {p.name: {'source': p.source_digest, 'operations': [(o.name, o.version) for o in p.operations]}
                          for p in providers}}).encode()).hexdigest()
        self.core = None

    def install(self, core, portal):
        check(self.core is None and not (set(self.credentials) & set(core.adapters)), 'INTEGRATION_ALREADY_REGISTERED')
        self.core = core
        for service in self.credentials: core.adapters[service] = ExtensionAdapter(self, self.providers[service])
        for key, policy in self.rules.items(): core.policies[key] = policy
        portal.strong_operations |= frozenset((s, o) for (a, s, o, t), p in self.rules.items() if p == 'ASK')
        core.policy_version += ':extensions-' + self.digest
        return self

    def _access(self, credential, service, operation, target):
        actor = self.core.auth.authenticate(credential)
        check((actor, service, operation, target) in self.rules, 'INTEGRATION_GRANT_DENIED')
        policy = self.core._policy(actor, {'service': service, 'operation': operation, 'target': target})
        check(policy in ('ALLOW', 'ASK'), 'INTEGRATION_OPERATION_DENIED')
        return actor

    def call(self, credential, value):
        fields = {'requestId', 'service', 'operation', 'target', 'params', 'reason'}
        check(type(value) is dict and set(value) == fields, 'INTEGRATION_CALL_SCHEMA')
        # Core's strict envelope binds ID/service/operation/target/reason and bounds JSON.
        body = {**deepcopy(value), 'expectedVersion': 0}
        self.core._payload(body)
        self._access(credential, value['service'], value['operation'], value['target'])
        op = self.operations[(value['service'], value['operation'])]
        forbid_credentials(value['params']); validate_with(op.params, value['params'], limit=32768)
        row = self.core.client(credential, 'submit', body)
        return {'requestId': row['requestId'], 'state': row['state']}

    def result(self, credential, request_id, *, reconcile=False):
        check(type(reconcile) is bool, 'INTEGRATION_RESULT_SCHEMA')
        row = self.core.client(credential, 'status', request_id)
        req = row['request']
        self._access(credential, req['service'], req['operation'], req['target'])
        if reconcile and row['state'] in ('DISPATCHED', 'UNCERTAIN'):
            row = self.core.reconcile(request_id)
        data = None
        if row['state'] == 'EXECUTED':
            result = row['result']; self.core.adapters[req['service']].confirm(request_id, result)
            data = result['data']
        return bounded({'requestId': row['requestId'], 'state': row['state'],
            'service': req['service'], 'operation': req['operation'], 'target': req['target'], 'data': data})

    def catalog(self, credential):
        actor = self.core.auth.authenticate(credential)
        return self.catalog_for(actor)

    def catalog_for(self, actor):
        rows = []
        for (principal, service, operation, target), configured_policy in sorted(self.rules.items()):
            if principal != actor: continue
            op = self.operations[(service, operation)]
            policy = configured_policy if self.core is None else self.core._policy(actor,
                {'service': service, 'operation': operation, 'target': target})
            ready = {'configured': True, 'ready': True, 'status': 'NOT_REQUIRED'}
            if policy != 'DENY' and op.credential:
                ready = self.vault.readiness(self.credentials[service][op.credential])
            rows.append({'service': service, 'operation': operation, 'kind': op.kind,
                'description': op.description, 'version': op.version,
                'target': target, 'policy': policy, 'ready': policy != 'DENY' and ready['ready'],
                'credential': ready, 'providerPermissions': 'UNVERIFIED'})
        return bounded({'schemaVersion': 1, 'configurationDigest': self.digest, 'operations': rows}, 262144)
