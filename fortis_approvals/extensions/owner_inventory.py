"""Owner-session-only inventory projection of installed Gateway policy configuration.

This is a read model, not a policy editor or an authorization source.
Only the currently loaded/configured runtime is visible: it is *not* a
filesystem scan of all possible plugins or proof of remote provider health.
"""
from .model import bounded


POLICIES = frozenset(('DENY', 'ASK', 'ALLOW'))


def literal_effective(core, actor, service, operation, target):
    # Never run configured predicate callbacks during an inventory READ.
    for key in ((actor, service, operation, target),
                (actor, service, operation), (service, operation)):
        if key in core.policies:
            rule = core.policies[key]
            return rule if type(rule) is str and rule in POLICIES else 'UNKNOWN'
    return 'DENY'


def owner_policy_inventory(core, extension_runtime=None):
    """Return secret-free policy rows; never execute a provider operation."""
    rows = []
    extension_services = set(extension_runtime.providers) if extension_runtime else set()
    services = {name: {'provider': name, 'type': 'native', 'active': True,
                       'configured': False, 'sourceDigest': None}
                for name in core.adapters if name not in extension_services}
    # Native policy keys can be global, actor-wide or actor/target-exact.
    # A global/actor policy is not necessarily the effective policy for every
    # target; target-specific overrides and predicates must be accounted for.
    for key, rule in sorted(core.policies.items(), key=lambda item: repr(item[0])):
        if type(key) is not tuple or len(key) not in (2, 3, 4):
            continue
        if not all(type(part) is str for part in key):
            continue
        if len(key) == 2:
            service, operation = key
            actor, target, scope = None, None, 'global'
        elif len(key) == 3:
            actor, service, operation = key
            target, scope = None, 'actor'
        else:
            actor, service, operation, target = key
            scope = 'exact'
        if service in extension_services:
            continue
        services.setdefault(service, {'provider': service, 'type': 'native',
            'active': service in core.adapters, 'configured': False, 'sourceDigest': None})
        services[service]['configured'] = True
        configured = rule if type(rule) is str and rule in POLICIES else 'CONDITIONAL'
        # Only exact scoped literal rules have an unambiguous effective readback.
        effective = 'UNKNOWN'
        if scope == 'exact':
            effective = literal_effective(core, actor, service, operation, target)
        rows.append({'provider': service, 'providerType': 'native',
            'operation': operation, 'version': None, 'kind': 'unknown',
            'actor': actor, 'target': target, 'scope': scope,
            'configuredPolicy': configured, 'effectivePolicy': effective,
            'configured': True, 'active': service in core.adapters,
            'handlerReady': None, 'credentialStatus': 'UNVERIFIED',
            'upstreamStatus': 'UNVERIFIED'})
    if extension_runtime is not None:
        rt = extension_runtime
        for service, provider in sorted(rt.providers.items()):
            configured = service in rt.credentials
            services[service] = {'provider': service, 'type': 'extension',
                'active': service in core.adapters and configured,
                'configured': configured, 'sourceDigest': provider.source_digest}
            for op in sorted(provider.operations, key=lambda item: item.name):
                grants = [(actor, target, policy)
                    for (actor, svc, operation, target), policy in rt.rules.items()
                    if svc == service and operation == op.name]
                if not grants:
                    grants = [(None, None, 'DENY')]
                for actor, target, policy in sorted(grants, key=lambda row: (str(row[0]), str(row[1]))):
                    effective = 'DENY' if actor is None else 'UNKNOWN'
                    if actor is not None:
                        effective = literal_effective(core, actor, service, op.name, target)
                    status = 'NOT_REQUIRED'
                    if effective in ('ASK', 'ALLOW') and (op.credential or op.signing_credential):
                        status = 'READY'
                    if effective in ('ASK', 'ALLOW'):
                        roles = (op.credential, op.signing_credential)
                        for role in roles:
                            if not role:
                                continue
                            alias = rt.credentials.get(service, {}).get(role)
                            if alias is None:
                                status = 'MISSING'
                                break
                            try:
                                state = rt.vault.readiness(alias)
                                if state.get('status') != 'READY' or state.get('ready') is not True:
                                    status = 'NOT_READY'
                                    break
                            except Exception:
                                status = 'NOT_READY'
                                break
                    rows.append({'provider': service, 'providerType': 'extension',
                        'operation': op.name, 'version': op.version, 'kind': op.kind,
                        'actor': actor, 'target': target, 'scope': 'exact' if actor else 'unconfigured',
                        'configuredPolicy': policy, 'effectivePolicy': effective,
                        'configured': actor is not None, 'active': services[service]['active'],
                        'handlerReady': op.ready, 'credentialStatus': status,
                        'upstreamStatus': 'UNVERIFIED'})
    result = {'schemaVersion': 1, 'coverage': 'LOADED_GATEWAY_RUNTIME_ONLY',
        'policyVersion': core.policy_version, 'providers': sorted(services.values(), key=lambda p: p['provider']),
        'operations': sorted(rows, key=lambda p: (p['provider'], p['operation'], str(p['actor']), str(p['target'])))}
    return bounded(result, 262144)
