"""P3.4: trusted startup composition, no live activation or credentials."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.integrations.github.publisher_owner_mount import (
    load_owner_publisher_mount,
)
from fortis_approvals.integrations.github.publisher_profile import (
    ACTOR as PUBLISHER, READS, WRITES, PublisherProfile,
)
from fortis_approvals.integrations.github.pilot import GitHubPilotConfig
from fortis_approvals.r7_unified_candidate import (
    ACTOR as REPO, build_r7_unified_candidate,
)
from publisher_fixture import API, Backend


REPO_GRANT = 'r7-review-repo-grant-00000000000000001'
PUBLISHER_GRANT = 'r7-review-publisher-grant-00000000001'
REVISION = 'd' * 64
VALIDATOR = 'a' * 40
MOUNT_CONFIG = dict(schemaVersion=1, enabled=True, actor=PUBLISHER,
                    repository='fortis-approvals', revision=REVISION,
                    validatorRevision=VALIDATOR, registryDelegation=True)


class Sonar:
    def call(self, *args, **kwargs):
        raise AssertionError('Sonar transport cannot be reached in this test')


class OwnerMountTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name) / 'publisher-private-mount'

    def write(self, config=None, grant=PUBLISHER_GRANT):
        self.root.mkdir(mode=0o700)
        profile = self.root / 'profile.json'
        profile.write_text(json.dumps(MOUNT_CONFIG if config is None else config))
        profile.chmod(0o600)
        credential = self.root / 'grant'
        credential.write_text(grant + '\n')
        credential.chmod(0o600)
        return profile, credential

    def test_unmounted_is_explicitly_disabled(self):
        self.assertEqual(load_owner_publisher_mount(self.root), (None, None))
        self.assertFalse(self.root.exists())

    def test_owner_private_mount_returns_exact_enabled_profile(self):
        self.write()
        profile, grant = load_owner_publisher_mount(self.root)
        self.assertEqual(grant, PUBLISHER_GRANT)
        self.assertTrue(profile.enabled)
        self.assertEqual(profile.validator_revision, VALIDATOR)
        self.assertEqual(profile.revision, REVISION)
        self.assertTrue(profile.registry_delegation)

    def test_partial_or_unexpected_mount_stops_without_fallback(self):
        self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(RuntimeError, 'INCOMPLETE'):
            load_owner_publisher_mount(self.root)
        (self.root / 'stray').write_text('test')
        with self.assertRaisesRegex(RuntimeError, 'INCOMPLETE'):
            load_owner_publisher_mount(self.root)

    def test_profile_rejects_unreviewed_actor_revision_and_schema(self):
        cases = [
            {'actor':'repo-sonar-read-proposal-actor'},
            {'repository':'rd-graphs'},
            {'enabled':False},
            {'registryDelegation':False},
            {'revision':'f'*40},
            {'validatorRevision':'b'*64},
            {'schemaVersion':2},
            {'schemaVersion':True},
            {'unexpected':'data'},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                self.write({**MOUNT_CONFIG, **changes})
                with self.assertRaises(RuntimeError):
                    load_owner_publisher_mount(self.root)
                for file in self.root.iterdir():
                    file.unlink()
                self.root.rmdir()

    def test_duplicate_json_keys_fail_closed(self):
        profile, _ = self.write()
        profile.write_text(profile.read_text()[:-1] + ', "enabled": true}')
        with self.assertRaises(RuntimeError):
            load_owner_publisher_mount(self.root)

    def test_grant_and_mount_permissions_symlinks_fail_closed(self):
        profile, grant = self.write()
        for item in (profile, grant):
            item.chmod(0o644)
            with self.assertRaises(RuntimeError):
                load_owner_publisher_mount(self.root)
            item.chmod(0o600)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, 'MOUNT_INSECURE'):
            load_owner_publisher_mount(self.root)
        self.root.chmod(0o700)
        grant.unlink()
        grant.symlink_to(profile)
        with self.assertRaises(RuntimeError):
            load_owner_publisher_mount(self.root)

    def test_invalid_grant_and_symlink_mount_stop(self):
        _, grant = self.write(grant='short')
        with self.assertRaisesRegex(RuntimeError,'GRANT_INVALID'):
            load_owner_publisher_mount(self.root)
        outside = Path(self.folder.name)/'link'
        outside.symlink_to(self.root)
        with self.assertRaisesRegex(RuntimeError,'MOUNT_INSECURE'):
            load_owner_publisher_mount(outside)


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.profile = PublisherProfile(
            enabled=True, revision=REVISION, validator_revision=VALIDATOR,
            registry_delegation=True)
        self.config = GitHubPilotConfig(
            'AlexPastukhh', 'fortis-approvals', native_worktree=True, ci_reads=True,
            required_workflows=(408327525,414303977),
            file_pr_branch='fortis-e2e/11111111-1111-4111-8111-111111111111-approve')
        self.calls = 0

    def build(self, *, profile=None, grant=None, actor_grants=None, github_pilot='use-default'):
        self.calls += 1
        state=self.root/f'state-{self.calls}'
        state.mkdir(mode=0o700)
        if github_pilot == 'use-default':
            github_pilot=self.config
        with patch('fortis_approvals.workflow.runtime.GitHubGitBackend', return_value=Backend()):
            return build_r7_unified_candidate(
                state=state, owner_origin='http://localhost:19203',
                ingress_host='host.docker.internal:19204',
                ingress_grant=REPO_GRANT, actor_grants=actor_grants,
                sonar_transport=Sonar(), organizations=('fortis-review',),
                github_pilot=github_pilot, github_transport=API(),
                publisher_profile=profile, publisher_grant=grant)

    def test_default_unchanged_and_publisher_unrecognized(self):
        core, _, _, ingress = self.build()
        self.assertFalse(core.auth.active(PUBLISHER))
        self.assertTrue(core.auth.active(REPO))
        self.assertFalse(ingress.publisher.enabled)
        self.assertNotIn(PUBLISHER, ingress.base.broker.actor_operations)

    def test_distinct_publisher_is_github_only_and_repo_unchanged(self):
        core, _, _, ingress = self.build(profile=self.profile,grant=PUBLISHER_GRANT)
        self.assertEqual(core.auth.authenticate(PUBLISHER_GRANT), PUBLISHER)
        self.assertEqual(core.auth.authenticate(REPO_GRANT), REPO)
        broker=ingress.base.broker
        self.assertEqual(broker.actor_operations[PUBLISHER],
                         frozenset(('github', op) for op in WRITES))
        self.assertEqual(broker.actor_read_operations[PUBLISHER],
                         frozenset(('github', op) for op in READS))
        for action in WRITES:
            self.assertEqual(core._policy(PUBLISHER,dict(
                service='github',operation=action,target='fortis-approvals')), 'ASK')
        for action in READS:
            self.assertEqual(core._policy(PUBLISHER,dict(
                service='github',operation=action,target='fortis-approvals')), 'ALLOW')
        for op in ('accept_issue','get_quality_gate','create_release_label',
                   'push_commits','merge_pull_request'):
            service='sonarcloud' if op in ('accept_issue','get_quality_gate') else 'github'
            self.assertEqual(core._policy(PUBLISHER,dict(
                service=service,operation=op,target='fortis-approvals')), 'DENY')
        self.assertEqual(core._policy(REPO,dict(
            service='sonarcloud',operation='accept_issue',target='fortis-review')), 'ASK')
        self.assertTrue(ingress.publisher.enabled)
        self.assertEqual(ingress.publisher.capabilities('AlexPastukhh', REPO)['publisherProfile']['enabled'],True)

    def test_server_rejects_publisher_grant_reused_as_sonar_token(self):
        from fortis_approvals import r7_unified_server
        with (patch.object(r7_unified_server, '_private_ascii',
                           side_effect=[REPO_GRANT, PUBLISHER_GRANT]),
              self.assertRaisesRegex(RuntimeError, 'CREDENTIAL_REUSE_DENIED')):
            r7_unified_server.create_servers(
                state=str(self.root/'not-created'),
                grant_path='/not-read/repo-grant',
                sonar_token_path='/not-read/sonar-token',
                cert_path='/not-read/cert', key_path='/not-read/key',
                region='eu', organizations=('fortis-review',),
                project_key='fortis-review',
                publisher_profile=self.profile, publisher_grant=PUBLISHER_GRANT)
        self.assertFalse((self.root/'not-created').exists())

    def test_altered_untrusted_grant_inventory_and_activation_pair_fail(self):
        cases = [
            dict(profile=self.profile,grant=None),
            dict(profile=None,grant=PUBLISHER_GRANT),
            dict(profile=PublisherProfile(),grant=PUBLISHER_GRANT),
            dict(profile=self.profile,grant=REPO_GRANT),
            dict(profile=self.profile,grant='short'),
            dict(profile=self.profile,grant=PUBLISHER_GRANT,github_pilot=None),
            dict(profile=self.profile,grant=PUBLISHER_GRANT,
                 actor_grants={REPO_GRANT: REPO,PUBLISHER_GRANT:PUBLISHER}),
            dict(profile=None,grant=None,
                 actor_grants={REPO_GRANT:PUBLISHER}),
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises((Denied, ValueError)):
                self.build(**case)


if __name__=='__main__':
    unittest.main()
