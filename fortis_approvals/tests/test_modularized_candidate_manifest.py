"""Source-only packaging checks for the modularized Gateway candidate.

No Docker build, token provisioning, volume creation, registration or deployment.
"""
from pathlib import Path
import shlex
import fnmatch
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "fortis_approvals/deploy/Dockerfile-Gateway-Modularized-Candidate"


class ModularizedCandidateManifestTests(unittest.TestCase):
    def test_live_e2e_text_is_non_release_data_but_source_and_neighbor_paths_stay_manifested(self):
        import importlib.util
        from unittest.mock import patch
        spec=importlib.util.spec_from_file_location('source_manifests',ROOT/'scripts/update-source-manifests.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            excluded='docs/fortis-e2e/11111111-1111-4111-8111-111111111111.txt'
            included=['docs/fortis-e2e/code.py','docs/fortis-e2e/test.txt',
                'docs/fortis-e2e-other/11111111-1111-4111-8111-111111111111.txt','fortis_approvals/runtime.py']
            for name in [excluded,*included]:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture')
            with patch.object(module,'ROOT',root),patch.object(module,'FULL',root/'docs/MODULARIZED-SOURCE-MANIFEST.sha256'):
                names={name for name,_ in module.full_rows()}
            self.assertNotIn(excluded,names)
            self.assertEqual(names,set(included))

    def test_provider_package_allowlist_and_no_github_activation(self):
        src = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("COPY fortis_approvals/integrations/ /opt/fortis/fortis_approvals/integrations/", src)
        self.assertIn("COPY fortis_approvals/extensions/ /opt/fortis/fortis_approvals/extensions/", src)
        self.assertIn("COPY fortis_approvals/clients/ /opt/fortis/fortis_approvals/clients/", src)
        # Owner Portal imports the opt-in shell client during module load. The
        # curated image must include it even when shell execution is disabled.
        self.assertIn("fortis_approvals/owner_shell.py ", src)
        self.assertIn("fortis_approvals/owner_shell_portal.py ", src)
        self.assertIn("fortis_approvals/incidents.py ", src)
        self.assertIn("fortis_approvals/owner_inventory.py ", src)
        self.assertIn("fortis_approvals/workflow/incident_read.py ", src)
        self.assertIn("IMAGE_OWNER_INCIDENT_IMPORT_PASS",
                      (ROOT/'fortis_approvals/deploy/image_offline_smoke.py').read_text())
        self.assertNotIn("COPY . ", src)
        ignored=(ROOT/'.dockerignore').read_text().splitlines()
        for entry in ('**/tests','**/.env','**/*.key','**/*.pem','**/*.sqlite','**/private'):
            self.assertIn(entry,ignored)
        self.assertNotIn("fortis-github-token", src)
        self.assertNotIn("/run/github-token", src)
        self.assertNotIn("FORTIS_GITHUB_TOKEN", src)
        self.assertIn("USER 10001:10001", src)
        self.assertIn('CMD ["python","-m","fortis_approvals.r7_unified_server"]', src)

    def test_exact_copy_candidate_imports_sonar_and_disabled_github(self):
        lines = [line.strip() for line in DOCKERFILE.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        copies = [shlex.split(line)[1:] for line in lines if line.startswith("COPY ")]
        self.assertGreaterEqual(len(copies), 7)
        # Candidate inputs match files eligible for Git archive; ignored scratch
        # files must not make a pre-commit packaging check falsely pass.
        eligible = set(subprocess.check_output(
            ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
            cwd=ROOT).decode().split('\0'))
        with tempfile.TemporaryDirectory(prefix="fortis-modularized-image-") as tmp:
            root = Path(tmp)
            for parts in copies:
                destination_text = parts[-1]
                destination_text = destination_text.removeprefix("/opt/fortis/")
                destination_text = destination_text.removeprefix("/opt/")
                target = root / destination_text
                sources = [ROOT / item for item in parts[:-1]]
                if len(sources) == 1 and sources[0].is_dir():
                    for source in sources[0].rglob("*"):
                        relative = source.relative_to(ROOT).as_posix()
                        excludes = (ROOT / '.dockerignore').read_text().splitlines()
                        if source.is_file() and relative in eligible and not any(
                            fnmatch.fnmatch(relative, pattern) or any(
                                fnmatch.fnmatch('/'.join(source.relative_to(ROOT).parts[:n]), pattern)
                                for n in range(1, len(source.relative_to(ROOT).parts)))
                            for pattern in excludes):
                            rel = source.relative_to(sources[0])
                            out = target / rel
                            out.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copyfile(source, out)
                elif len(sources) == 1 and not destination_text.endswith("/"):
                    self.assertIn(sources[0].relative_to(ROOT).as_posix(), eligible)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(sources[0], target)
                else:
                    target.mkdir(parents=True, exist_ok=True)
                    for source in sources:
                        self.assertIn(source.relative_to(ROOT).as_posix(), eligible)
                        shutil.copyfile(source, target / source.name)
            self.assertFalse(list(root.rglob('tests')))
            self.assertFalse(list(root.rglob('*.key')))
            code = (
                "import sys; "
                f"sys.path.insert(0, {str(root)!r}); "
                "import fortis_approvals.r7_unified_server; "
                "from fortis_approvals.integrations.github.registration "
                "import register_github_integration; "
                "from fortis_approvals.integrations.github.gateway.adapter "
                "import GitHubAdapter; "
                "from fortis_approvals.integrations.github.gateway.transport "
                "import GitHubHTTPTransport; "
                "print('MODULARIZED_GATEWAY_IMPORTS_PASS'); "
                + "exec(" + repr((ROOT / "fortis_approvals/deploy/image_offline_smoke.py").read_text()) + ")"
            )
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-c", code],
                cwd=tmp, capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(completed.returncode, 0,
                             completed.stdout + "\n" + completed.stderr)
            self.assertIn("MODULARIZED_GATEWAY_IMPORTS_PASS", completed.stdout)

    def test_review_compose_uses_dedicated_state_and_alternate_origins(self):
        deploy = ROOT / "fortis_approvals/deploy"
        compose = (deploy / "compose-modularized-review-20261105.yaml").read_text()
        self.assertIn("127.0.0.1:19203:19103", compose)
        self.assertIn("127.0.0.1:19204:19104", compose)
        self.assertIn('FORTIS_OWNER_ORIGIN: "http://localhost:19203"', compose)
        self.assertIn('FORTIS_MACHINE_HOST: "host.docker.internal:19204"', compose)
        self.assertIn("name: fortis-r7-state-review-20261105", compose)
        self.assertNotRegex(compose, r"name:\s+fortis-r7-state(?:\r?\n|$)")
        self.assertIn("read_only: true", compose)

    def test_review_restore_and_start_scripts_keep_production_separate(self):
        deploy = ROOT / "fortis_approvals/deploy"
        restore = (deploy / "Restore-R7-State-Backup-To-ModularizedReview-20261105.ps1").read_text()
        start = (deploy / "Start-Modularized-Review-20261105.ps1").read_text()
        self.assertIn("fortis-r7-state-review-20261105", restore)
        helper = (deploy / "restore_review_state.py").read_text()
        self.assertIn("TARGET_ORIGIN = 'http://localhost:19203'", helper)
        self.assertIn("target=/backup,readonly", restore)
        self.assertIn("fortis-r7-state-review-20261105", start)
        self.assertIn("PRODUCTION_IDENTITY_OR_HEALTH_MISMATCH", start)
        self.assertIn("PRODUCTION_CUTOVER=NOT_PERFORMED", start)
        self.assertNotIn("docker.exe stop", start)
        self.assertNotIn("docker.exe rm", start)
