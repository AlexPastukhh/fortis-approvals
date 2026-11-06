"""Offline tests of the exact image-side config admission code in the updater.

PowerShell, Docker lifecycle and Windows ACLs remain real owner-run checks.
"""
from contextlib import redirect_stdout
import io
import importlib.util
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied

SCRIPT = Path(__file__).resolve().parents[1] / 'deploy' / 'Update-NativeReview.ps1'
CONFIG_CODE = re.search(r"\$Validate=@'\n(.*?)\n'@", SCRIPT.read_text(), re.S).group(1)


def config(**changes):
    value = dict(owner='AlexPastukhh', sonarMutations=False, bindings={
        'obs-planning-docs': dict(projectKey='AlexPastukhh_obs-planning-docs',
            workflows={'123456': '.github/workflows/sonar.yml'}, allowCiControl=False)})
    value.update(changes)
    return value


def validate(raw):
    output = io.StringIO()
    with patch('sys.stdin', io.StringIO(raw)), patch('sys.path', list(__import__('sys').path)), redirect_stdout(output):
        exec(compile(CONFIG_CODE, '<updater-config>', 'exec'), {})
    return json.loads(output.getvalue())


class UpdateConfigTests(unittest.TestCase):
    def test_exact_config_survives_stdin_and_compaction_without_grant_expansion(self):
        value = config()
        self.assertEqual(validate(json.dumps(value, indent=2)), value)
        self.assertFalse(validate(json.dumps(value))['sonarMutations'])

    def test_other_owner_or_project_denied_before_container_stop(self):
        for value in (config(owner='OtherOwner'), config(bindings={
            'obs-planning-docs': dict(projectKey='OtherProject',
                workflows={'123456': '.github/workflows/sonar.yml'}, allowCiControl=False)})):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                validate(json.dumps(value))

    def test_unknown_fields_empty_binding_and_arbitrary_workflow_path_denied(self):
        for value in (config(extra=True), config(bindings={}), config(bindings={
            'obs-planning-docs': dict(projectKey='AlexPastukhh_obs-planning-docs',
                workflows={'123456': '../arbitrary.yml'}, allowCiControl=False)})):
            with self.subTest(value=value), self.assertRaises(Denied):
                validate(json.dumps(value))

    def test_duplicate_json_key_and_non_json_denied(self):
        for raw in ('not json', '{"owner":"Other","owner":"AlexPastukhh"}', ''):
            with self.subTest(raw=raw), self.assertRaises(Denied): validate(raw)

    def test_repo_exec_contract_and_client_probe_precede_source_stop(self):
        source = SCRIPT.read_text()
        function = re.search(r'function Repo-Python-Arguments \{(.*?)\n\}', source, re.S).group(1)
        self.assertIn("@('exec','-i','--user','1000:1000','fortis-repo-test','python3','-I','-B','-c',$Wrapper)", function)
        self.assertLess(source.index('$PreflightClientChecks=Check-Clients'), source.index("Set-Step 'STOP_SOURCE'"))
        self.assertIn("$script:R.clientChecks=Check-Clients", source)
        self.assertIn("UPDATE_REPO_ARGV_SELFTEST_FAILED", source)

    def test_all_embedded_python_compiles_without_host_or_provider_access(self):
        for code in re.findall(r"\$\w+=@'\n(.*?)\n'@", SCRIPT.read_text(), re.S):
            compile(code, '<updater-embedded-python>', 'exec')


class UpdatePackageTests(unittest.TestCase):
    def test_standalone_copy_is_deterministic_and_has_no_external_asset_reads(self):
        root = SCRIPT.parents[2]
        spec = importlib.util.spec_from_file_location('package_update', root / 'scripts/package-review-update.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        first = module.build(root, 'a' * 40)
        self.assertEqual(first, module.build(root, 'a' * 40))
        source = first.decode()
        self.assertNotIn('Join-Path $PSScriptRoot', source)
        self.assertIn("$ProductionImage = 'sha256:e751", source)
        self.assertIn('param(\n    [ValidateSet', source)
        self.assertIn('function Private-Process {', source)
        self.assertIn('UPDATE_WINDOWS_POWERSHELL_51_REQUIRED', source)
        self.assertIn('ANALYSIS_OPERATIONS_DISABLED_CONFIGURATION_PENDING', source)
        import base64
        embedded = re.findall(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", source)
        decoded = {base64.b64decode(item) for item in embedded}
        for filename in ('github_pilot_helpers.py', 'image_offline_smoke.py'):
            self.assertIn((SCRIPT.parent / filename).read_bytes(), decoded)
