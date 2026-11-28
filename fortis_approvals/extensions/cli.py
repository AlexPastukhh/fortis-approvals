"""Source/operator tooling. Provision reads confidential stdin, never argv/env.

No machine route invokes this CLI. Host Docker commands remain owner-run.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

from ..core import Denied, canonical, loads_strict
from .vault import CredentialVault, name
from .model import RESERVED, check, discover, ident
from .runtime import ExtensionConfig, ExtensionRuntime

DEFAULT_ACTOR = 'repo-sonar-read-proposal-actor'


def stdin_json(limit=65536):
    raw = sys.stdin.buffer.read(limit + 1)
    check(0 < len(raw) <= limit, 'INTEGRATION_INPUT_LIMIT')
    return loads_strict(raw)


def check_config(value, vault=None):
    config = ExtensionConfig(value)
    providers = discover(tuple(config.value['providers']))
    actors = {DEFAULT_ACTOR}  # The supported R7 launcher provisions this one machine actor.
    runtime = ExtensionRuntime(config, providers=providers, actors=tuple(actors), default_actor=DEFAULT_ACTOR, vault=vault)
    reports = [runtime.catalog_for(actor) for actor in sorted(actors)]
    missing = set()
    for service, settings in config.value['providers'].items():
        for rule_name, rule in settings['operations'].items():
            if rule['policy'] == 'DENY': continue
            op = runtime.operations[(service, rule_name)]
            if op.credential:
                alias = settings['credentials'][op.credential]
                if not runtime.vault.readiness(alias)['ready']: missing.add(alias)
    return {'status': 'READY' if not missing else 'CREDENTIALS_REQUIRED',
        'configurationDigest': runtime.digest, 'missingCredentials': sorted(missing),
        'operations': [row for report in reports for row in report['operations']]}


def scaffold(root, service):
    """One provider package, no registry/CI/Docker edit; stub cannot be enabled."""
    ident(service); check(service not in RESERVED, "INTEGRATION_PROVIDER_RESERVED")
    root = Path(root).resolve()
    directory = root / 'fortis_approvals' / 'integrations' / service
    check((root / 'fortis_approvals/extensions/model.py').is_file(), 'INTEGRATION_SOURCE_ROOT_INVALID')
    check(not directory.exists() and not directory.is_symlink(), 'INTEGRATION_PROVIDER_EXISTS')
    directory.mkdir(mode=0o755)
    (directory / '__init__.py').write_text('"""' + service + ' provider integration."""\n')
    code = '''"""Replace the fixed API/routes/schema and handler; then set ready=True.

No tokens, environment IO or network calls at module import.
"""
from fortis_approvals.extensions.model import Operation, Provider
from fortis_approvals.extensions.http import JSONAPI, Route
from fortis_approvals.integrations.review_schema import object_schema, text


def read_item(ctx):
    # ctx.call('get_item', path={'id': ctx.target}) performs Gateway-only auth.
    raise NotImplementedError('Implement and test the provider response projection')


PROVIDER = Provider('SERVICE_ID', (
    Operation('read_item', 'Read one permitted item', 'read',
              object_schema({}), object_schema({'value': text}), read_item,
              credential='api', routes=('get_item',), ready=False),
), api=JSONAPI('https://api.example.invalid', (
    Route('get_item', 'GET', '/items/{id}', readonly=True),
)))
'''.replace('SERVICE_ID', service)
    (directory / 'extension.py').write_text(code)
    (directory / 'README.md').write_text('# ' + service + '\n\nSource stub, disabled. Implement/test extension.py; define exact scopes/ALLOW or ASK in trusted config.\nCredential values go only to the Gateway credential volume through owner tooling.\n')
    tests = directory / 'tests'; tests.mkdir()
    (tests / 'test_definition.py').write_text('''"""Replace with provider schema/route/effect regression checks before enabling."""
import unittest
from fortis_approvals.integrations.SERVICE_ID.extension import PROVIDER

class DefinitionTests(unittest.TestCase):
    def test_unfinished_definition_stays_disabled(self):
        self.assertFalse(PROVIDER.operations[0].ready)
'''.replace('SERVICE_ID', service))
    return {'status': 'SCAFFOLDED_DISABLED', 'provider': service, 'path': str(directory)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('check', 'credential', 'scaffold', 'catalog', 'probe', 'activate', 'credential-status', 'gate-status', 'gate-record-status'))
    parser.add_argument('--root', default='/run/fortis-secrets')
    parser.add_argument('--source-root')
    parser.add_argument('--name')
    args = parser.parse_args()
    try:
        if args.command == 'scaffold':
            check(args.source_root and args.name, 'INTEGRATION_SCAFFOLD_INPUT_REQUIRED')
            result = scaffold(args.source_root, args.name)
        elif args.command == 'credential':
            value = stdin_json()
            check(type(value) is dict and {'name', 'value'} <= set(value) <= {'name', 'value', 'expectedGeneration'}, 'CREDENTIAL_INPUT_INVALID')
            vault = CredentialVault(args.root); vault.initialize()
            result = vault.provision(value['name'], value['value'], expected_generation=value.get('expectedGeneration'))
        elif args.command == 'credential-status':
            check(args.name, 'CREDENTIAL_NAME_REQUIRED')
            vault = CredentialVault(args.root); status = vault.readiness(args.name)
            result = {'name': args.name, **status}
            if status['ready']: result['generation'] = vault.get(args.name).generation
        elif args.command == 'gate-record-status':
            from .staging import ReleaseGate
            value = stdin_json()
            check(type(value) is dict and set(value) == {'nonce', 'configurationDigest'}, 'RELEASE_GATE_INPUT_INVALID')
            result = ReleaseGate(value['nonce'], value['configurationDigest']).record_status()
        elif args.command == 'gate-status':
            from .staging import ReleaseGate
            config = ExtensionConfig(loads_strict(os.environ.get('FORTIS_EXTENSIONS_CONFIG', '')))
            runtime = ExtensionRuntime(config, providers=discover(tuple(config.value['providers'])),
                actors=(DEFAULT_ACTOR,), default_actor=DEFAULT_ACTOR)
            result = {'active': ReleaseGate(os.environ.get('FORTIS_RELEASE_NONCE'), runtime.digest).ready(),
                'configurationDigest': runtime.digest}
        elif args.command == 'check':
            result = check_config(stdin_json(), CredentialVault(args.root))
        elif args.command == 'activate':
            from .staging import ReleaseGate
            value = loads_strict(os.environ.get('FORTIS_EXTENSIONS_CONFIG', ''))
            config = ExtensionConfig(value)
            runtime = ExtensionRuntime(config, providers=discover(tuple(config.value['providers'])),
                actors=(DEFAULT_ACTOR,), default_actor=DEFAULT_ACTOR)
            nonce = os.environ.get('FORTIS_RELEASE_NONCE')
            ReleaseGate(nonce, runtime.digest).activate()
            result = {'status': 'ACTIVATED', 'configurationDigest': runtime.digest}
        else:
            from .client import IntegrationClient, IntegrationTransport
            host = os.environ.get('FORTIS_MACHINE_HOST')
            check(host == 'host.docker.internal:19204', 'INTEGRATION_OWNER_REVIEW_ENDPOINT_REQUIRED')
            client = IntegrationClient(gateway=IntegrationTransport(endpoint='https://' + host,
                grant_path='/run/r7-grant/grant', certificate_path='/run/r7-identity/server.crt', allow_test_endpoint=True,
                max_response_bytes=262144))
            if args.command == 'catalog': result = client.catalog()
            else:
                probes = stdin_json(); check(type(probes) is list and len(probes) <= 20, 'INTEGRATION_PROBES_INVALID')
                catalog = client.catalog(); count = 0
                for probe in probes:
                    check(type(probe) is dict and set(probe) == {'service', 'operation', 'target', 'params'}, 'INTEGRATION_PROBE_INVALID')
                    rows = [r for r in catalog['operations'] if all(r[k] == probe[k] for k in ('service', 'operation', 'target'))]
                    check(len(rows) == 1 and rows[0]['kind'] == 'read' and rows[0]['policy'] == 'ALLOW' and rows[0]['ready'], 'INTEGRATION_UNSAFE_PROBE')
                    row = client.call(**probe, reason='Owner-reviewed integration read-only release probe')
                    check(row['state'] == 'EXECUTED', 'INTEGRATION_PROBE_NOT_EXECUTED')
                    check(client.result(row['requestId'])['state'] == 'EXECUTED', 'INTEGRATION_PROBE_RESULT_UNAVAILABLE')
                    count += 1
                result = {'status': 'READ_PROBES_PASS', 'count': count, 'mutationEffectsVerified': False}
        print(canonical(result))
    except Exception as exc:
        # Never include exception text: parsers, provider SDKs or filesystem paths
        # can contain secrets. Only fixed public codes leave this owner pipe.
        code = str(exc) if isinstance(exc, Denied) and re.fullmatch('[A-Z][A-Z0-9_]{1,100}', str(exc)) else 'INTEGRATION_TOOL_FAILED'
        print(canonical({'error': code}), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__': main()
