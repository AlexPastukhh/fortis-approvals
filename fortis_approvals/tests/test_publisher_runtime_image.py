"""P3.4 image packaging is source-only; no Docker daemon or network required."""
import glob
import json
import os
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
