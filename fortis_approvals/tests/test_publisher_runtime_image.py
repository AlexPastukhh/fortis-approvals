"""P3.4 image packaging is source-only; no Docker daemon or network required."""
import glob
import json
import os
import shlex
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / 'fortis_approvals/deploy/Dockerfile-P3-Release-Label-Publisher'
CATALOG = ROOT / 'release/targets.yaml'


def copied_modules(directory):
    """Emulate reviewed COPY file selection, not a Docker isolation claim."""
    lines = DOCKERFILE.read_text().splitlines()
    staged = directory / 'python-path'
    copied = []
    for row in lines:
        if not row.startswith('COPY '):
            continue
        fields = row.split()
        dest = fields[-1]
        prefix = '/site-packages/fortis_approvals/'
        if prefix not in dest:
            raise AssertionError('PUBLISHER_IMAGE_DESTINATION_DENIED')
        destination = staged / 'fortis_approvals' / dest.split(prefix,1)[1]
        destination.mkdir(parents=True,exist_ok=True)
        for token in fields[1:-1]:
            assert token.startswith('fortis_approvals/') and '..' not in token
            selected = glob.glob(str(ROOT/token))
            assert selected, token
            for source in selected:
                assert Path(source).is_file(), source
                target = destination / Path(source).name
                shutil.copyfile(source,target)
                copied.append(str(Path(source).relative_to(ROOT)))
    return staged, copied


class PublisherImageSourceTests(unittest.TestCase):
    def test_image_is_one_shot_nonroot_no_embedded_credentials(self):
        content = DOCKERFILE.read_text()
        self.assertIn('ARG PYTHON_BASE\nFROM ${PYTHON_BASE}',content)
        self.assertNotIn('ARG PYTHON_BASE=',content)
        self.assertIn('USER 10002:10002',content)
        self.assertIn('PYTHONDONTWRITEBYTECODE=1',content)
        self.assertIn('PYTHONNOUSERSITE=1',content)
        self.assertEqual([x for x in content.splitlines() if x.startswith('ENTRYPOINT ')],
                         ['ENTRYPOINT ["python3", "-I", "-B", "-m", "fortis_approvals.integrations.github.release_label_publisher"]'])
        for forbidden in ('EXPOSE ', 'HEALTHCHECK ', 'CMD ', 'VOLUME ', 'ADD ',
                          'FORTIS_GITHUB_TOKEN=', 'machine-grant=', 'curl ',
                          '--privileged', '/var/run/docker.sock'):
            self.assertNotIn(forbidden,content)

    @staticmethod
    def _pin_check(marker, environment):
        # Execute the exact inline build-arg validator without a Docker daemon.
        command = next(line for line in DOCKERFILE.read_text().splitlines()
                       if line.startswith('RUN python3 -c ') and marker in line)
        argv = shlex.split(command.removeprefix('RUN ').removesuffix(' \\'))
        assert argv[:2] == ['python3', '-c'], command
        return subprocess.run([sys.executable, '-c', argv[2]], env=environment,
                              capture_output=True, text=True, timeout=5)

    def test_dependency_snapshot_and_runtime_lock_are_mandatory(self):
        content = DOCKERFILE.read_text()
        self.assertIn('FROM ${PYTHON_BASE} AS publisher-deps', content)
        self.assertIn('FROM publisher-deps AS publisher-runtime', content)
        self.assertIn('https://snapshot.debian.org/archive/debian/', content)
        self.assertIn('https://snapshot.debian.org/archive/debian-security/', content)
        self.assertIn('signed-by=/usr/share/keyrings/debian-archive-keyring.gpg', content)
        self.assertNotIn('https://deb.debian.org', content)
        self.assertIn('"git=$PUBLISHER_GIT_VERSION"', content)
        self.assertIn('"ca-certificates=$PUBLISHER_CA_CERTIFICATES_VERSION"', content)
        self.assertIn('"zlib1g=$PUBLISHER_ZLIB_VERSION"', content)
        self.assertIn('os-packages.lock', content)
        self.assertIn('sha256sum --check --status', content)
        self.assertIn('org.opencontainers.image.revision=', content)
        base = {
            'PYTHON_BASE': 'python:3.11-slim@sha256:'+'a'*64,
            'PUBLISHER_APT_SNAPSHOT': '20261117T120000Z',
            'PUBLISHER_DEBIAN_CODENAME': 'trixie',
            'PUBLISHER_GIT_VERSION': '1:2.47.0-1',
            'PUBLISHER_CA_CERTIFICATES_VERSION': '20250419',
            'PUBLISHER_ZLIB_VERSION': '1:1.3.dfsg+really1.3.1-1+deb13u1',
        }
        run = self._pin_check('PUBLISHER_BUILD_PINS_REQUIRED', base)
        self.assertEqual(run.returncode, 0, run.stderr)
        for key, wrong in [
            ('PYTHON_BASE', 'python:3.11-slim'),
            ('PUBLISHER_APT_SNAPSHOT', 'latest'),
            ('PUBLISHER_APT_SNAPSHOT', '20261317T120000Z'),
            ('PUBLISHER_DEBIAN_CODENAME', 'sid'),
            ('PUBLISHER_GIT_VERSION', 'latest'),
            ('PUBLISHER_CA_CERTIFICATES_VERSION', '1;true'),
            ('PUBLISHER_ZLIB_VERSION', 'latest'),
        ]:
            with self.subTest(key=key, wrong=wrong):
                bad = {**base, key: wrong}
                self.assertNotEqual(self._pin_check('PUBLISHER_BUILD_PINS_REQUIRED', bad).returncode, 0)
        for key in base:
            with self.subTest(missing=key):
                bad = {k:v for k,v in base.items() if k != key}
                self.assertNotEqual(self._pin_check('PUBLISHER_BUILD_PINS_REQUIRED', bad).returncode, 0)
        final = {'PUBLISHER_OS_LOCK_SHA256': 'b'*64, 'PUBLISHER_SOURCE_SHA': 'c'*40}
        self.assertEqual(self._pin_check('PUBLISHER_RUNTIME_PINS_REQUIRED', final).returncode, 0)
        for bad in [
            {'PUBLISHER_OS_LOCK_SHA256':'latest', 'PUBLISHER_SOURCE_SHA':'c'*40},
            {'PUBLISHER_OS_LOCK_SHA256':'b'*64, 'PUBLISHER_SOURCE_SHA':'main'},
            {'PUBLISHER_OS_LOCK_SHA256':'b'*64},
            {},
        ]:
            self.assertNotEqual(self._pin_check('PUBLISHER_RUNTIME_PINS_REQUIRED', bad).returncode, 0)

    def test_only_selected_python_modules_are_packaged(self):
        with tempfile.TemporaryDirectory() as directory:
            staged, paths = copied_modules(Path(directory))
            self.assertGreater(len(paths),20)
            self.assertTrue((staged/'fortis_approvals/integrations/github/release_label_publisher.py').is_file())
            for forbidden in ('fortis_approvals/r7_unified_server.py',
                              'fortis_approvals/owner_portal.py',
                              'fortis_approvals/server.py'):
                self.assertNotIn(forbidden,paths)
            self.assertFalse(any('/tests/' in x or x.endswith(('.key','.pem','.sqlite'))
                                 for x in paths))
            self.assertEqual(len(paths),len(set(paths)))

    def test_isolated_python_import_and_cli_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            staged, _ = copied_modules(Path(directory))
            preamble='import sys;sys.path.insert(0,%r);' % str(staged)
            base=[sys.executable,'-I','-B','-c']
            environ={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}
            code=preamble+'from fortis_approvals.integrations.github.release_label_publisher import main;main(["--help"])'
            result=subprocess.run(base+[code],capture_output=True,text=True,
                                  cwd=directory,env=environ,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('{preview,request,inspect}',result.stdout)
            # The live one-shot runner imports the explicit publisher-only
            # WorkflowClient lazily. Include that path in packaging smoke;
            # CLI --help alone does not exercise it.
            code=preamble+('from fortis_approvals.workflow.client '
                           'import WorkflowClient, WorkflowTransport;'
                           'print("PUBLISHER_PRIVATE_CLIENT_IMPORT_PASS")')
            result=subprocess.run(base+[code],capture_output=True,text=True,
                                  cwd=directory,env=environ,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('PUBLISHER_PRIVATE_CLIENT_IMPORT_PASS',result.stdout)
            # No config/secret is shipped: a request must STOP before any
            # Gateway client or network interaction.
            code=preamble+('import json,sys;'
                 'from fortis_approvals.integrations.github.release_label_publisher import main;'
                 'sys.exit(main(["--config", "/run/publisher/missing.json",'
                 ' "request", "--pr", "118"]))')
            result=subprocess.run(base+[code],capture_output=True,text=True,
                                  cwd=directory,env=environ,timeout=10)
            self.assertEqual(result.returncode,2,result.stderr)
            value=json.loads(result.stdout)
            self.assertEqual(value['status'],'STOP')
            self.assertFalse(value['writeEnabled'])

    def test_catalog_registers_separate_immutable_image_target(self):
        catalog=CATALOG.read_text()
        self.assertIn('id: publisher-runner-image',catalog)
        self.assertIn('id: release-label-publisher',catalog)
        self.assertIn('recipe: fortis_approvals/deploy/Dockerfile-P3-Release-Label-Publisher',catalog)
        self.assertIn('procedure: docs/P3-4-PUBLISHER-ISOLATED-RUNTIME.md',catalog)
        self.assertNotIn('buildUnit: primary-gateway-image\n    deployment:',catalog.split('id: release-label-publisher')[1])

if __name__=='__main__':
    unittest.main()
