"""Explicit config + shared Core for all extension ALLOW/ASK calls, including reads."""
from copy import deepcopy
from contextvars import ContextVar
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
        # Set by authenticated extension-call scope or persisted Core row.
        # A public params/URL actor is never identity evidence.
        self.authenticated_actor = authenticated_actor
        self._secret = None
        self._signing_alias = None
        self._signing_secret = None
        self._signing_generation = None
        self._signed_dispatch = None
        self._dispatch_used = False
        if operation.signing_credential:
            self._signing_alias = runtime.credentials[provider.name][operation.signing_credential]
            try:
                self._signing_secret = runtime.vault.get(self._signing_alias)
                self._signing_generation = self._signing_secret.generation
            except (OSError, Denied):
                raise Denied('INTEGRATION_SIGNING_CREDENTIAL_NOT_READY') from None
        if operation.credential:
            alias = runtime.credentials[provider.name][operation.credential]
            try: self._secret = runtime.vault.get(alias)
            except (OSError, Denied): raise Denied('INTEGRATION_CREDENTIAL_NOT_READY') from None

    @property
    def generation(self):
        return None if self._secret is None else self._secret.generation

    @property
    def signing_generation(self):
        return self._signing_generation

    def sign_mirror_dispatch(self, persisted_identity, *, preview_expires_at):
        """Execution-only Ed25519 proof for the *verified* immutable P4 preview.

        Trusted Mirror operation code must first compare persisted_identity to
        the actor-bound stored preview and fresh preconditions. This method is
        not a public API and does not authorize a Windows effect by itself.
        """
        check(self.phase == 'execute' and self.provider.name == 'mirror' and
              self.operation.name == 'execute_windows_pull_v2' and
              self.operation.kind == 'write' and self._signing_alias is not None and
              type(self.authenticated_actor) is str and bool(self.authenticated_actor),
              'MIRROR_SIGNING_PHASE_DENIED')
        check(type(persisted_identity) is dict and set(persisted_identity) ==
              {'previewId', 'expectedHead', 'targetSha', 'configGeneration'} and
              persisted_identity == self.params,
              'MIRROR_SIGNING_IDENTITY_INVALID')
        check(self._signed_dispatch is None and not self._dispatch_used,
              'MIRROR_SIGNING_ALREADY_USED')
        approved = self.runtime.core._read(self.request_id)
        check(approved['state'] == 'DISPATCHED' and approved['decision'] == 'approve' and
              type(approved['owner']) is str and bool(approved['owner']) and
              approved['actor'] == self.authenticated_actor and
              approved['request']['service'] == 'mirror' and
              approved['request']['operation'] == self.operation.name and
              approved['request']['target'] == self.target and
              approved['request']['params'] == self.params,
              'MIRROR_SIGNING_APPROVAL_REQUIRED')
        try:
            current = self.runtime.vault.get(self._signing_alias)
            transport = self.runtime.vault.get(
                self.runtime.credentials[self.provider.name][self.operation.credential])
        except (OSError, Denied):
            raise Denied('MIRROR_SIGNING_CREDENTIAL_REVOKED') from None
        check(current.generation == self._signing_generation and
              self._secret is not None and transport.generation == self._secret.generation,
              'MIRROR_SIGNING_CREDENTIAL_REVOKED')
        from fortis_approvals.integrations.mirror.signing import sign_dispatch_identity
        identity = dict(issuer='fortis-gateway', audience='fortis-mirror',
            service='mirror', operation='execute_windows_pull_v2',
            requestId=self.request_id, actor=self.authenticated_actor,
            repoId=self.target, **persisted_identity)
        proof = sign_dispatch_identity(identity, key_id=self.operation.signing_key_id,
            secret=current, preview_expires_at=preview_expires_at)
        self._signed_dispatch = deepcopy(proof)
        return proof

    def safe(self, value):
        bounded(value)
        forbid_credentials(value)
        if self._secret is not None or self._signing_secret is not None:
            # No WRITE bearer or signer seed may escape through schema output,
            # including JSON-escaped strings or nested keys.
            tokens = tuple(secret.reveal() for secret in
                           (self._secret, self._signing_secret) if secret is not None)
            def contains(item):
                if type(item) is str: return any(token in item for token in tokens)
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
        if not definition.readonly and self.operation.signing_credential is not None:
            # A matching one-use signed dispatch is mandatory even with a WRITE
            # bearer. An earlier lost response must not trigger a second POST.
            expected = {'requestId': self.request_id, 'repoId': self.target,
                'actor': self.authenticated_actor, **self.params,
                'proof': self._signed_dispatch}
            check(self.phase == 'execute' and self._signed_dispatch is not None and
                  not self._dispatch_used and type(body) is dict and
                  body == expected and set(body) == set(expected),
                  'MIRROR_SIGNED_DISPATCH_REQUIRED')
            # A revoked/rotated signer or WRITE bearer never dispatches a
            # previously constructed proof with stale local credentials.
            try:
                signer = self.runtime.vault.get(self._signing_alias)
                transport = self.runtime.vault.get(self.runtime.credentials[self.provider.name]
                    [self.operation.credential])
            except (OSError, Denied):
                raise Denied('MIRROR_SIGNING_CREDENTIAL_REVOKED') from None
            check(self._signing_generation == signer.generation and
                  self._secret is not None and self._secret.generation == transport.generation,
                  'MIRROR_SIGNING_CREDENTIAL_REVOKED')
            self._dispatch_used = True  # before network, including lost ACK
        return self.provider.api.call(route, credential=self._secret, path=path, query=query,
                                      body=body, request_id=self.request_id)


class ExtensionAdapter:
    def __init__(self, runtime, provider):
        self.runtime, self.provider = runtime, provider

    def operation(self, request):
        check(request['service'] == self.provider.name, 'INTEGRATION_SERVICE_DENIED')
        return self.runtime.operations[(self.provider.name, request['operation'])]

    def prepare(self, request):
        # Core is immutable under the pinned persistence-source gate. The
        # extension call owns a scoped, authenticated principal BEFORE submit;
        # Core's persisted request row owns it on revalidation/execute.
        scope = self.runtime._preflight_identity.get()
        try:
            row = self.runtime.core._read(request['requestId'])
        except Denied:
            row = None
        if row is not None:
            check(row['request'] == request, 'INTEGRATION_CORE_IDENTITY_INVALID')
            actor = row['actor']
            if scope is not None:
                check(scope == (actor, request['requestId']),
                      'INTEGRATION_PRINCIPAL_CHANGED')
        else:
            actor = None
            if scope is not None:
                check(scope[1] == request['requestId'], 'INTEGRATION_REQUEST_ID_CHANGED')
                actor = scope[0]
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
        snapshot = {'summary': op.description, 'effect': op.kind, 'target': request['target'],
            'params': request['params'], 'before': preview, 'credentialGeneration': ctx.generation,
            'definitionDigest': self.runtime.digest}
        if op.signing_credential is not None:
            snapshot['signingGeneration'] = ctx.signing_generation
        return ctx.safe(snapshot)

    def apply(self, request):
        op = self.operation(request)
        row = self.runtime.core._read(request['requestId'])
        check(row['state'] == 'DISPATCHED' and row['request'] == request,
              'INTEGRATION_CORE_IDENTITY_INVALID')
        ctx = Context(self.runtime, self.provider, op, request, 'execute',
                      authenticated_actor=row['actor'])
        # Recheck frozen domain inputs and credential generation at the effect boundary.
        if canonical(self.prepare(request)) != canonical(row['preview']):
            raise Stale('INTEGRATION_PREVIEW_CHANGED')
        check(ctx.generation == row['preview']['credentialGeneration'], 'INTEGRATION_CREDENTIAL_CHANGED')
        if op.signing_credential is not None:
            check(ctx.signing_generation == row['preview']['signingGeneration'],
                  'INTEGRATION_SIGNING_CREDENTIAL_CHANGED')
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
        # Scoped to one integration call, not one process/thread; reset on
        # success and failure so no later actor or request can inherit it.
        self._preflight_identity = ContextVar('fortis_extension_preflight_identity', default=None)
        self.providers = {x.name: x for x in providers}
        self.operations = {(p.name, o.name): o for p in providers for o in p.operations}
        self.vault = vault or CredentialVault()
        self.credentials, self.rules = {}, {}
        global_signing_aliases, global_transport_aliases = set(), set()
        check(default_actor in actors, 'INTEGRATION_ACTOR_INVALID')
        for service, settings in config.value['providers'].items():
            check(service in self.providers, 'INTEGRATION_PROVIDER_NOT_PACKAGED')
            check(type(settings) is dict and set(settings) == {'credentials', 'operations'}, 'INTEGRATION_CONFIG_INVALID')
            credentials, operations = settings['credentials'], settings['operations']
            definitions = self.providers[service].operations
            known_credentials = {x.credential for x in definitions if x.credential}
            known_credentials |= {x.signing_credential for x in definitions if x.signing_credential}
            check(type(credentials) is dict and set(credentials) <= known_credentials, 'INTEGRATION_CREDENTIAL_BINDING_INVALID')
            for alias in credentials.values(): credential_name(alias)
            signing_aliases = {credentials[x.signing_credential] for x in definitions
                               if x.signing_credential in credentials}
            transport_aliases = {credentials[x.credential] for x in definitions
                                 if x.credential in credentials}
            protected_write_aliases = {credentials[x.credential] for x in definitions
                                       if x.signing_credential and x.credential in credentials}
            read_aliases = {credentials[x.credential] for x in definitions
                            if x.kind == 'read' and x.credential in credentials}
            check(not protected_write_aliases.intersection(read_aliases),
                  'INTEGRATION_READ_WRITE_ROLE_COLLISION')
            check(not signing_aliases.intersection(transport_aliases),
                  'INTEGRATION_SIGNING_ROLE_COLLISION')
            global_signing_aliases.update(signing_aliases)
            global_transport_aliases.update(transport_aliases)
            self.credentials[service] = dict(credentials)
            check(type(operations) is dict and 1 <= len(operations) <= 100, 'INTEGRATION_CONFIG_INVALID')
            for operation, rule in operations.items():
                check((service, operation) in self.operations, 'INTEGRATION_OPERATION_NOT_PACKAGED')
                op = self.operations[(service, operation)]
                check(type(rule) is dict and {'policy', 'targets'} <= set(rule) <= {'policy', 'targets', 'actors'}, 'INTEGRATION_CONFIG_INVALID')
                check(rule['policy'] in ('ALLOW', 'ASK', 'DENY'), 'INTEGRATION_POLICY_INVALID')
                check(not op.signing_credential or rule['policy'] != 'ALLOW',
                      'INTEGRATION_SIGNING_REQUIRES_ASK')
                targets, principals = rule['targets'], rule.get('actors', [default_actor])
                check(type(targets) is list and 1 <= len(targets) <= 100 and
                      all(type(x) is str and TARGET.fullmatch(x) for x in targets) and len(set(targets)) == len(targets), 'INTEGRATION_TARGETS_INVALID')
                check(type(principals) is list and principals and all(type(x) is str for x in principals) and set(principals) <= set(actors) and
                      len(set(principals)) == len(principals), 'INTEGRATION_ACTOR_INVALID')
                if rule['policy'] != 'DENY':
                    check(op.ready, 'INTEGRATION_HANDLER_NOT_READY')
                    check(not op.credential or op.credential in credentials, 'INTEGRATION_CREDENTIAL_BINDING_MISSING')
                    check(not op.signing_credential or op.signing_credential in credentials,
                          'INTEGRATION_SIGNING_CREDENTIAL_BINDING_MISSING')
                for actor in principals:
                    for target in targets: self.rules[(actor, service, operation, target)] = rule['policy']
        check(not global_signing_aliases.intersection(global_transport_aliases),
              'INTEGRATION_SIGNING_ROLE_COLLISION')
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
        actor = self._access(credential, value['service'], value['operation'], value['target'])
        op = self.operations[(value['service'], value['operation'])]
        forbid_credentials(value['params']); validate_with(op.params, value['params'], limit=32768)
        marker = self._preflight_identity.set((actor, value['requestId']))
        try:
            row = self.core.client(credential, 'submit', body)
        finally:
            self._preflight_identity.reset(marker)
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
