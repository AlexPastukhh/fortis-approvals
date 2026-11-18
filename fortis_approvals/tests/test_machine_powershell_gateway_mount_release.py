"""Source-only owner-sealed machine PowerShell release: no credentials or Docker effects."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.powershell_owner_mount import (
    FILES, reviewed_machine_mount_digest,
)

ROOT = Path(__file__).resolve().parents[2]
PS = (ROOT / "fortis_approvals/deploy/Manage-Integrations.ps1").read_text()
HELPER = (ROOT / "fortis_approvals/deploy/github_pilot_helpers.py").read_text()
ACTOR = "repo-sonar-read-proposal-actor"
VOLUME = "fortis-r7-machine-powershell"
PROFILE = {
    "version": 1, "enabled": True, "mode": "ASK_ONLY",
    "actor": ACTOR, "target": "windows-owner",
    "sourceSha256": "a" * 64, "executorIdentity": "owner-nonadmin",
}


class FakeTransport:
    key = b"x" * 32

    def execute(self, *args):
        raise AssertionError("offline test cannot execute")

    def status(self, *args):
        raise AssertionError("offline test cannot read live state")


class MachineMountDigestTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "mount"
        self.root.mkdir(mode=0o700)
        for name in FILES:
            data = (json.dumps(PROFILE).encode() if name == "profile.json"
                    else ("SYNTHETIC_NOT_A_CREDENTIAL_" + name).encode())
            (self.root / name).write_bytes(data)
            (self.root / name).chmod(0o600)

    def digest(self):
        with patch("fortis_approvals.powershell_owner_mount.MachineShellTransport",
                   return_value=FakeTransport()):
            return reviewed_machine_mount_digest(expected_actor=ACTOR, root=self.root)

    def test_stable_and_sealed_all_six_bytes(self):
        digest = self.digest()
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(digest, self.digest())
        for name in FILES:
            old = (self.root / name).read_bytes()
            revised = (json.dumps(PROFILE, indent=2).encode()
                       if name == "profile.json" else old + b"x")
            (self.root / name).write_bytes(revised)
            self.assertNotEqual(digest, self.digest(), name)
            (self.root / name).write_bytes(old)
        self.assertNotIn("SYNTHETIC_", digest)

    def test_absent_or_bad_mount_fails_closed(self):
        self.root.rename(self.root.parent / "gone")
        with self.assertRaises(RuntimeError):
            self.digest()

    def test_denies_unsafe_permissions_symlinks_extra_and_allow(self):
        (self.root / "proof-key").chmod(0o644)
        with self.assertRaises(RuntimeError):
            self.digest()
        (self.root / "proof-key").chmod(0o600)
        (self.root / "extra").write_text("extra")
        with self.assertRaises(RuntimeError):
            self.digest()
        (self.root / "extra").unlink()
        (self.root / "bearer").unlink()
        (self.root / "bearer").symlink_to(self.root / "proof-key")
        with self.assertRaises(RuntimeError):
            self.digest()
        (self.root / "bearer").unlink()
        (self.root / "bearer").write_bytes(b"synthetic")
        (self.root / "bearer").chmod(0o600)
        (self.root / "profile.json").write_text(json.dumps({**PROFILE, "mode": "ALLOW"}))
        with self.assertRaises(RuntimeError):
            self.digest()


class DockerMountAdmissionTests(unittest.TestCase):
    def fixture(self):
        import test_github_pilot_package as pilot
        return pilot.AdmissionTests().fixture(), pilot.HELPERS

    def test_default_disabled_exact_volume_readonly_only(self):
        (container, expected), helpers = self.fixture()
        self.assertEqual(helpers.admit(container, expected, pilot=True),
                         {"admission": "PASS"})
        expected["machinePowerShellVolume"] = VOLUME
        with self.assertRaises(RuntimeError):
            helpers.admit(container, expected, pilot=True)
        mount = dict(Type="volume", Name=VOLUME,
                     Destination="/run/fortis-machine-powershell", RW=False,
                     Source="/var/lib/docker/volumes/" + VOLUME + "/_data")
        container["Mounts"].append(mount)
        self.assertEqual(helpers.admit(container, expected, pilot=True),
                         {"admission": "PASS"})
        expected["machinePowerShellVolume"] = ""
        with self.assertRaises(RuntimeError):
            helpers.admit(container, expected, pilot=True)

    def test_unknown_rw_host_relocation_rejected(self):
        (container, expected), helpers = self.fixture()
        for wrong in (None, True, "../../owner", "/host/secret",
                      "fortis-review-secrets", VOLUME + "-evil"):
            expected["machinePowerShellVolume"] = wrong
            with self.subTest(wrong=wrong), self.assertRaises(RuntimeError):
                helpers.admit(container, expected, pilot=True)
        expected["machinePowerShellVolume"] = VOLUME
        mount = dict(Type="volume", Name=VOLUME,
                     Destination="/run/fortis-machine-powershell", RW=False,
                     Source="/var/lib/docker/volumes/" + VOLUME + "/_data")
        container["Mounts"].append(mount)
        for field, wrong in (("RW", True), ("Type", "bind"),
                             ("Name", "different-volume"),
                             ("Destination", "/run/r7-grant"),
                             ("Source", "/tmp/attacker")):
            with self.subTest(field=field):
                old = mount[field]
                mount[field] = wrong
                with self.assertRaises(RuntimeError):
                    helpers.admit(container, expected, pilot=True)
                mount[field] = old


class CheckedReleaseWiringTests(unittest.TestCase):
    def test_manual_first_activation_and_checked_image_required(self):
        self.assertIn("[switch]$EnableMachinePowerShell", PS)
        self.assertIn("RELEASE_MACHINE_POWERSHELL_REQUIRES_EXACT_OWNER_CHECKED_IMAGE", PS)
        self.assertIn("$Auto -or $Action -cnotin @('Check','Apply')", PS)
        self.assertIn("($Action -eq 'Check' -and -not $Build)", PS)
        self.assertIn("($Action -eq 'Apply' -and (-not $CheckedImageRecord -or $Build))", PS)
        self.assertIn("$EnablePublisherMount -or $EnableMachinePowerShell", PS)
        self.assertNotIn("FORTIS_MACHINE_POWERSHELL_ENABLED=", PS)

    def test_checked_fingerprint_and_recovery_inherit_volume(self):
        self.assertIn("machinePowerShellVolume=$script:MachinePowerShellVolume", PS)
        self.assertIn("machinePowerShellDigest=$script:MachinePowerShellDigest", PS)
        self.assertIn("enableMachinePowerShell=[bool]$EnableMachinePowerShell", PS)
        self.assertIn("Read-MachinePowerShellVolume $SourceForOwnerShell.runtime", PS)
        self.assertIn("Read-MachinePowerShellDigest $SourceForOwnerShell.runtime", PS)
        self.assertIn("machinePowerShellVolume=(Read-MachinePowerShellVolume $P)", PS)
        self.assertIn("RELEASE_MACHINE_POWERSHELL_SOURCE_MATERIAL_CHANGED", PS)
        self.assertIn("RELEASE_MACHINE_POWERSHELL_CONTENT_CHANGED", PS)

    def test_offline_preflight_and_last_docker_mount(self):
        section = PS.split("function Image-MachinePowerShell-Preflight {", 1)[1].split(
            "function Get-SourceRecord {", 1)[0]
        self.assertIn("'--network','none','--read-only'", section)
        self.assertIn("'--user','10001:10001','--cap-drop','ALL'", section)
        self.assertIn("reviewed_machine_mount_digest", section)
        self.assertIn("target=/run/fortis-machine-powershell,readonly", section)
        create = PS.split("Step 'CREATE_STAGED'", 1)[1].split(
            "$script:R.runtime.pilotId=Docker-Text $Arguments", 1)[0]
        self.assertIn("if($Runtime.machinePowerShellVolume)", create)
        self.assertIn("target=/run/fortis-machine-powershell,readonly", create)
        self.assertLess(create.index("target=/run/fortis-machine-powershell,readonly"),
                        create.index("$Arguments+=@($script:Image)"))
        self.assertNotIn("volume','create','fortis-r7-machine-powershell'", PS)
        self.assertIn("machine_volume = expected.get('machinePowerShellVolume', '')", HELPER)


if __name__ == "__main__":
    unittest.main()
