"""Small trusted-code definition API. Public config cannot supply code or URLs."""
from dataclasses import dataclass, field
import hashlib
import importlib
from pathlib import Path
import re

from ..core import Denied, canonical

IDENT = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
TARGET = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z')
RESERVED = frozenset({'github', 'sonarcloud', 'workspace', 'synthetic'})


def check(value, code='INTEGRATION_DEFINITION_INVALID'):
    if not value: raise Denied(code)


def ident(value):
    check(type(value) is str and IDENT.fullmatch(value))
    return value


def bounded(value, limit=65536):
    try:
        check(len(canonical(value).encode()) <= limit, 'INTEGRATION_RESULT_LIMIT')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise Denied('INTEGRATION_JSON_INVALID') from None
    return value


def forbid_credentials(value):
    if type(value) is dict:
        for key, item in value.items():
            check(type(key) is str, 'INTEGRATION_PARAMS_INVALID')
            check(key.lower().replace('_', '').replace('-', '') not in
                  {'token', 'accesstoken', 'refreshtoken', 'apikey', 'authorization',
                   'credential', 'credentials', 'secret', 'password', 'privatekey'},
                  'INTEGRATION_CALLER_CREDENTIAL_DENIED')
            forbid_credentials(item)
    elif type(value) is list:
        for item in value: forbid_credentials(item)


@dataclass(frozen=True)
class Operation:
    name: str
    description: str
    kind: str  # read or write; ALLOW/ASK is selected independently in trusted config
    params: object
    result: object
    execute: object
    preview: object = None
    preview_result: object = None
    lookup: object = None
    credential: str = None
    routes: tuple = ()
    version: str = '1'
    ready: bool = True
    # Additive optional fields preserve legacy positional Operation definitions.
    signing_credential: str = None
    signing_key_id: str = None
    # Empty for legacy hand-written providers; reviewed compiled methods supply a closed scope.
    allowed_targets: tuple = ()

    def __post_init__(self):
        ident(self.name)
        check(self.kind in ('read', 'write') and type(self.description) is str and
              1 <= len(self.description.encode()) <= 1000 and type(self.version) is str and
              1 <= len(self.version) <= 64 and type(self.ready) is bool)
        check(all(callable(x) for x in (self.params, self.result, self.execute)))
        check(self.kind != 'write' or callable(self.preview) and callable(self.preview_result))
        check(self.preview is None or callable(self.preview))
        check(self.preview_result is None or callable(self.preview_result))
        check(self.lookup is None or callable(self.lookup))
        check(self.credential is None or type(self.credential) is str and IDENT.fullmatch(self.credential))
        check((self.signing_credential is None) == (self.signing_key_id is None),
              'INTEGRATION_SIGNING_DEFINITION_INVALID')
        if self.signing_credential is not None:
            check(self.kind == 'write' and self.credential is not None and
                  type(self.signing_credential) is str and IDENT.fullmatch(self.signing_credential) and
                  self.signing_credential != self.credential and
                  type(self.signing_key_id) is str and
                  re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', self.signing_key_id),
                  'INTEGRATION_SIGNING_DEFINITION_INVALID')
        check(type(self.routes) is tuple and len(set(self.routes)) == len(self.routes) and
              all(type(x) is str and IDENT.fullmatch(x) for x in self.routes))
        check(type(self.allowed_targets) is tuple and len(self.allowed_targets) <= 100 and
              all(type(t) is str and TARGET.fullmatch(t) for t in self.allowed_targets) and
              len(set(self.allowed_targets)) == len(self.allowed_targets),
              'INTEGRATION_OPERATION_TARGET_SCOPE_INVALID')


@dataclass(frozen=True)
class Provider:
    name: str
    operations: tuple
    api: object = None
    source_digest: str = field(default='trusted-injected-definition', repr=False)

    def __post_init__(self):
        ident(self.name); check(self.name not in RESERVED)
        check(type(self.operations) is tuple and 1 <= len(self.operations) <= 100 and
              all(isinstance(x, Operation) for x in self.operations))
        check(len({x.name for x in self.operations}) == len(self.operations), 'INTEGRATION_DUPLICATE_OPERATION')
        for operation in self.operations:
            check(not operation.routes or self.api is not None and
                  set(operation.routes) <= set(self.api.routes), 'INTEGRATION_ROUTE_NOT_REGISTERED')


def discover(names=None):
    """Load selected image-owned integrations/<service>/extension.py definitions.

    Config selects an already packaged service ID, never a module path. Disabled
    providers are not imported and cannot acquire unrelated SDK/secret dependencies.
    """
    from .. import integrations
    from dataclasses import replace
    root = Path(integrations.__file__).resolve().parent
    available = {p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink() and
                 not p.name.startswith('_') and (p / 'extension.py').is_file()}
    selected = sorted(available if names is None else names)
    check(len(selected) <= 50 and len(set(selected)) == len(selected))
    result = []
    for service in selected:
        ident(service)
        check(service not in RESERVED and service in available, 'INTEGRATION_PROVIDER_NOT_PACKAGED')
        folder = root / service; source = folder / 'extension.py'
        check(not source.is_symlink() and source.resolve().parent == folder.resolve(), 'INTEGRATION_MODULE_ORIGIN_INVALID')
        files = sorted(folder.rglob('*.py'))
        check(not any(p.is_symlink() for p in files), 'INTEGRATION_MODULE_ORIGIN_INVALID')
        module = importlib.import_module(integrations.__name__ + '.' + service + '.extension')
        check(Path(module.__file__).resolve() == source.resolve(), 'INTEGRATION_MODULE_ORIGIN_INVALID')
        provider = module.PROVIDER
        check(isinstance(provider, Provider) and provider.name == service)
        digest = hashlib.sha256()
        for path in files:
            if 'tests' not in path.relative_to(folder).parts and '__pycache__' not in path.parts:
                digest.update(path.relative_to(folder).as_posix().encode()); digest.update(path.read_bytes())
        result.append(replace(provider, source_digest=digest.hexdigest()))
    return tuple(result)
