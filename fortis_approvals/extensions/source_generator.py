"""Image-owned, source-only generation of reviewed extension provider packages.

No untrusted OpenAPI execution, runtime hot loading, network calls, credentials,
or Gateway policy changes. The CLI writes only to an explicitly supplied source
worktree. Preview is the default. Normal source PR/CI/image release still apply.
"""
import argparse
import subprocess
from pathlib import Path
from pprint import pformat
from types import SimpleNamespace

from ..core import Denied, canonical, loads_strict
from . import source_workspace
from .declarative_read import compile_read_provider
from .http import JSONAPI, Route
from .model import Operation, Provider, RESERVED, check, ident

# These are source formats/transport choices, NOT No-code/Low-code/Custom
# workflow modes. All outcomes feed the same package and release process.
_PACKAGE_KEYS = ('schemaVersion', 'provider', 'transport', 'origin', 'routes', 'methods')
_ROUTE_KEYS = ('name', 'path', 'queryKeys')
_MANIFEST = 'generated-inventory.json'
_MARKER = '# FORTIS-SOURCE-GENERATED-PROVIDER-V1'


def _source(value):
    """Reject non-JSON Python objects, noncanonical key types and oversized input."""
    try:
        data = canonical(value)
        check(len(data.encode('utf-8')) <= 65536, 'SOURCE_DESCRIPTION_LIMIT')
        result = loads_strict(data)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise Denied('SOURCE_DESCRIPTION_NOT_JSON') from None
    check(type(result) is dict and set(result) == set(_PACKAGE_KEYS) and
          type(result['schemaVersion']) is int and result['schemaVersion'] == 1,
          'SOURCE_DESCRIPTION_INVALID')
    ident(result['provider'])
    check(result['provider'] not in RESERVED, 'SOURCE_PROVIDER_RESERVED')
    check(result['transport'] in ('jsonapi', 'manual'), 'SOURCE_TRANSPORT_UNSUPPORTED')
    if result['transport'] == 'jsonapi':
        check(type(result['origin']) is str, 'SOURCE_ORIGIN_INVALID')
    else:
        check(result['origin'] is None, 'SOURCE_ORIGIN_INVALID')
    check(type(result['routes']) is list and 1 <= len(result['routes']) <= 100 and
          type(result['methods']) is list and len(result['methods']) <= 100,
          'SOURCE_ROUTES_OR_METHODS_INVALID')
    return result


def _routes(source):
    routes = []
    for item in source['routes']:
        check(type(item) is dict and set(item) == set(_ROUTE_KEYS),
              'SOURCE_ROUTE_SCHEMA_INVALID')
        check(type(item['queryKeys']) is list and len(item['queryKeys']) <= 20 and
              all(type(v) is str for v in item['queryKeys']),
              'SOURCE_ROUTE_SCHEMA_INVALID')
        routes.append(Route(item['name'], 'GET', item['path'], readonly=True,
                            query_keys=tuple(item['queryKeys'])))
    check(len({route.name for route in routes}) == len(routes),
          'SOURCE_ROUTE_DUPLICATE')
    return tuple(routes)


def _route_match(api, expected):
    check(api is not None and type(api.routes) is dict,
          'SOURCE_MANUAL_TRANSPORT_NOT_READY')
    check(set(api.routes)=={r.name for r in expected},
          'SOURCE_MANUAL_ROUTE_MISMATCH')
    for route in expected:
        supplied=api.routes.get(route.name)
        check(isinstance(supplied,Route) and supplied == route,
              'SOURCE_MANUAL_ROUTE_MISMATCH')


def _assert_compilable(source):
    expected = _routes(source)
    if source['transport'] == 'jsonapi':
        # Creating a JSONAPI does NOT send HTTP or read credentials.
        api=JSONAPI(source['origin'], expected)
    else:
        api=SimpleNamespace(routes={r.name:r for r in expected})
    if source['methods']:
        compile_read_provider(source['provider'],api,tuple(source['methods']))
    return expected


def build_generated_provider(description, manual):
    """Executed only by trusted, image-packaged extension.py at import time."""
    spec=_source(description)
    # The actual trusted transport below is compiled exactly once.
    expected=_routes(spec)
    for key in ('make_transport','result_postchecks','context_postchecks','manual_operations'):
        check(callable(getattr(manual,key,None)), 'SOURCE_MANUAL_CONTRACT_INVALID')
    if spec['transport']=='jsonapi':
        api=JSONAPI(spec['origin'], expected)
    else:
        api=manual.make_transport()
        _route_match(api,expected)
    postchecks=manual.result_postchecks()
    context_checks=manual.context_postchecks()
    created=() if not spec['methods'] else compile_read_provider(
        spec['provider'],api,tuple(spec['methods']),postchecks=postchecks,
        context_checks=context_checks).operations
    extra=manual.manual_operations()
    check(type(extra) is tuple and all(isinstance(op,Operation) for op in extra),
          'SOURCE_MANUAL_OPERATIONS_INVALID')
    # No unmatched result/context checks when all methods are manual.
    if not spec['methods']:
        check(not postchecks and not context_checks, 'SOURCE_MANUAL_HOOK_WITHOUT_METHOD')
    return Provider(spec['provider'], created+extra,api=api)


_EXTENSION = '''"""Generated entry: source-owned operations + preserved manual additions."""
%s
from fortis_approvals.extensions.source_generator import build_generated_provider
from .definition import SOURCE_DESCRIPTION
from . import manual
PROVIDER = build_generated_provider(SOURCE_DESCRIPTION,manual)
''' % _MARKER

_MANUAL = '''"""Trusted hand-written extension parts. NEVER overwritten by generator.

Only source-reviewed code should be placed here. No network/credential reads at
module import. Manual Operation and transport must keep existing Gateway safety
contracts, scoped credentials, preview/receipt and standard approval flow.
"""
from fortis_approvals.core import Denied


def make_transport():
    # Implement and test when the source description declares manual transport.
    raise Denied('MANUAL_TRANSPORT_REQUIRED')


def result_postchecks():
    # Return {method_name: callable(value)}; revalidated by Operation.result.
    return {}


def context_postchecks():
    # Return {method_name: callable(target, params, value)}; execute-only.
    return {}


def manual_operations():
    # Return tuple of fully source-owned Operation instances, if required.
    return ()
'''

_GENERATED_TEST = '''"""Generated structural baseline tests. Never replace test_manual.py."""
import unittest
from fortis_approvals.integrations.%s.extension import PROVIDER
from fortis_approvals.integrations.%s.definition import SOURCE_DESCRIPTION

class GeneratedContractTests(unittest.TestCase):
    def test_source_provider_and_compiled_method_presence(self):
        self.assertEqual(PROVIDER.name,SOURCE_DESCRIPTION['provider'])
        self.assertTrue({row['name'] for row in SOURCE_DESCRIPTION['methods']} <=
                        {op.name for op in PROVIDER.operations})
    def test_source_routes_are_readonly(self):
        self.assertTrue(all(PROVIDER.api.routes[r['name']].method=='GET' and
                        PROVIDER.api.routes[r['name']].readonly
                        for r in SOURCE_DESCRIPTION['routes']))
'''

_MANUAL_TEST = '''"""Hand-written regression tests for custom source components. Preserved."""
'''


def _render_validated(source):
    """Render a single normalized source description without re-validating."""
    name=source['provider']
    content='"""Reviewed, source-owned definition; never fetched at runtime."""\n' + \
        'SOURCE_DESCRIPTION = '+pformat(source,sort_dicts=True,width=100)+'\n'
    methods=', '.join(row['name'] for row in source['methods']) or '(manual-only)'
    return {
        '__init__.py':'"""Generated Fortis provider package."""\n',
        'extension.py':_EXTENSION,
        'definition.py':content,
        'tests/test_compiled_contract.py':_GENERATED_TEST%(name,name),
        'CONTRACT.generated.md':('# Source-generated provider contract\n\n'
                                 'Provider: `%s`\n\nTransport: `%s`\n\n'
                                 'Compiled methods: %s\n\n'
                                 'Manual operations and hooks: `manual.py` (preserved).\n'
                                 'Source PR, tests, owner config and release are still required.\n'
                                 % (name,source['transport'],methods)),
    }



def _prepared(description):
    source=_source(description)
    _assert_compilable(source)
    return source,_render_validated(source)


def render_package(description):
    """Deterministic validated in-memory package; never touches the source tree."""
    return _prepared(description)[1]


def source_plan(root,description):
    """Read-only preliminary change list; never mutates source or reviews."""
    source,generated=_prepared(description)
    return source_workspace.preview(root,source['provider'],generated)


def _git_value(root,*args):
    try:
        proc=subprocess.run(['git','-C',str(root),*args],capture_output=True,
                            text=True,check=False,timeout=10)
    except (OSError,subprocess.TimeoutExpired):
        raise Denied('SOURCE_TASK_WORKTREE_REQUIRED') from None
    check(proc.returncode==0 and proc.stdout.strip(),
          'SOURCE_TASK_WORKTREE_REQUIRED')
    return proc.stdout.strip()


def _check_task_worktree(root):
    """Require an actual linked task worktree of THIS installed source repo.

    Merely writing `task/*` to a fake .git config or using a directory without
    Git does not meet the boundary. The canonical module and target must share
    a git-common-dir, and Git must list the target as an exact registered worktree.
    """
    candidate=Path(root).absolute()
    check(candidate.is_dir() and not candidate.is_symlink() and
          candidate==candidate.resolve(strict=True) and
          (candidate/'.git').is_file() and not (candidate/'.git').is_symlink(),
          'SOURCE_TASK_WORKTREE_REQUIRED')
    owner=Path(__file__).resolve().parents[2]
    target_top=Path(_git_value(candidate,'rev-parse','--show-toplevel')).resolve()
    check(target_top==candidate,'SOURCE_TASK_WORKTREE_REQUIRED')
    target_common=Path(_git_value(candidate,'rev-parse','--path-format=absolute',
                                  '--git-common-dir')).resolve()
    owner_common=Path(_git_value(owner,'rev-parse','--path-format=absolute',
                                 '--git-common-dir')).resolve()
    check(target_common==owner_common,'SOURCE_TASK_WORKTREE_REQUIRED')
    branch=_git_value(candidate,'symbolic-ref','--quiet','HEAD')
    check(branch.startswith('refs/heads/task/'), 'SOURCE_TASK_WORKTREE_REQUIRED')
    listing=_git_value(owner,'worktree','list','--porcelain')
    records=[dict(line.split(' ',1) for line in block.splitlines()
                  if ' ' in line)
             for block in listing.split('\n\n') if block.strip()]
    check(any(Path(row.get('worktree','/missing')).resolve()==candidate and
              row.get('branch')==branch for row in records),
          'SOURCE_TASK_WORKTREE_REQUIRED')


def apply_source_package(root,description):
    """Source-only staged package update; never an image install or live grant."""
    _check_task_worktree(root)
    source,generated=_prepared(description)
    return source_workspace.apply(root,source['provider'],generated,
        {'manual.py':_MANUAL,'tests/test_manual.py':_MANUAL_TEST})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',required=True)
    parser.add_argument('--descriptor',required=True)
    parser.add_argument('--evidence',help='Required before source --apply: reviewed API capability facts')
    parser.add_argument('--apply',action='store_true',help='Write only to the explicit source task worktree')
    args=parser.parse_args()
    source=loads_strict(Path(args.descriptor).read_text(encoding='utf-8'))
    if args.apply:
        # The public source CLI must evaluate the most economical valid option
        # before editing source. Programmatic fixture helpers remain testable.
        check(args.evidence is not None, 'SOURCE_ASSESSMENT_REQUIRED')
        from .source_strategy import advise_onboarding
        facts=loads_strict(Path(args.evidence).read_text(encoding='utf-8'))
        assessment=advise_onboarding(facts,source)
        check(assessment['status']!='REVIEW_REQUIRED',
              'SOURCE_ASSESSMENT_REVIEW_REQUIRED')
        # Until a persisted manual-requirements contract can be enforced on
        # discovered providers, do not publish a package whose mandatory hooks
        # or manual operations are silently absent. Keep its read-only plan and
        # manual handoff rather than generating a misleading READY package.
        check(assessment['status']=='SOURCE_PREFLIGHT_READY',
              'SOURCE_ASSESSMENT_MANUAL_REQUIRED')
        result=apply_source_package(args.source_root,source)
        result['assessmentDigest']=assessment['assessmentDigest']
        result['assessmentStatus']=assessment['status']
    else:
        result=source_plan(args.source_root,source)
    print(canonical(result))


if __name__=='__main__':
    main()
