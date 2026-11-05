"""Source-only packaging checks for the modularized Gateway candidate.

No Docker build, token provisioning, volume creation, registration or deployment.
"""
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "fortis_approvals/deploy/Dockerfile-Gateway-Modularized-Candidate"


class ModularizedCandidateManifestTests(unittest.TestCase):
    def test_provider_package_allowlist_and_no_github_activation(self):
        src = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("fortis_approvals/integrations/sonarcloud/gateway/", src)
        self.assertIn("fortis_approvals/integrations/github/gateway/", src)
        self.assertIn("fortis_approvals/integrations/github/registration.py", src)
        self.assertNotIn("integrations/github/repo_client", src)
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
                        if source.is_file():
                            rel = source.relative_to(sources[0])
                            out = target / rel
                            out.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copyfile(source, out)
                elif len(sources) == 1 and not destination_text.endswith("/"):
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(sources[0], target)
                else:
                    target.mkdir(parents=True, exist_ok=True)
                    for source in sources:
                        shutil.copyfile(source, target / source.name)
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
                "print('MODULARIZED_GATEWAY_IMPORTS_PASS')"
            )
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-c", code],
                cwd=tmp, capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(completed.returncode, 0,
                             completed.stdout + "\n" + completed.stderr)
            self.assertIn("MODULARIZED_GATEWAY_IMPORTS_PASS", completed.stdout)
