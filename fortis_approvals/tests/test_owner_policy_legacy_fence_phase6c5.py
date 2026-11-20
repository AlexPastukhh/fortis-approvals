"""Phase 6C.5 old IncidentCore R7 restart must not ignore local DENY.

No owner host, Docker, network, migration or live DB changes. This protects
only future code executing this guard; old binaries/existing workers bypass.
"""
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.incidents import IncidentCore
from fortis_approvals.r7_unified_candidate import build_r7_unified_candidate
from fortis_approvals.extensions.owner_policy_local_core_phase6c import LocalDenyCore
from fortis_approvals.extensions.owner_policy_legacy_fence_phase6c5 import (
    refuse_legacy_core_with_local_policy as guard)
from fortis_approvals.extensions.owner_policy_r7_optin_phase6c4 import (
    R7LocalDenySourceOptIn)
from fortis_approvals.tests.test_owner_policy_local_deny_http_phase6c2 import (
    HTTPFixtureWebAuthn)

GRANT='R7-SOURCE-TEST-GRANT-00000000000000000001'


class NoNetworkSonar:
    def call(self,method,path,params):
        raise AssertionError('UPSTREAM_EFFECT_FORBIDDEN')


class LegacyRestartFenceTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='fortis-legacy-fence-')
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.owner=HTTPFixtureWebAuthn()
        self.owner.origin='http://localhost:19103'
        self.sonar=NoNetworkSonar()
        self.kwargs=dict(state=self.root,owner_origin='http://localhost:19103',
            ingress_host='host.docker.internal:19104',ingress_grant=GRANT,
            sonar_transport=self.sonar,organizations=('acme',))

    def legacy(self):
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=self.owner):
            return build_r7_unified_candidate(**self.kwargs)

    def opted(self):
        with patch('fortis_approvals.r7_unified_candidate.IncidentOwnerWebAuthn',
                   return_value=self.owner):
            return build_r7_unified_candidate(**self.kwargs,
                local_deny_source_opt_in=R7LocalDenySourceOptIn('a'*64,'b'*64))

    def test_missing_database_is_noop_and_does_not_create_database(self):
        db=self.root/'approvals.sqlite'
        self.assertFalse(db.exists())
        self.assertEqual({'existingCoreDb':False,'legacyCoreAllowed':True},
                         guard(self.root))
        self.assertFalse(db.exists())

    def test_existing_legacy_db_unchanged_and_default_restart_still_allowed(self):
        first,_,_,_=self.legacy()
        dbpath=self.root/'approvals.sqlite'
        self.assertTrue(dbpath.exists())
        self.assertTrue(guard(self.root)['legacyCoreAllowed'])
        second,_,_,_=self.legacy()
        self.assertIs(type(first),IncidentCore)
        self.assertIs(type(second),IncidentCore)
        self.assertFalse(hasattr(second,'_local_policy_initialized'))

    def test_local_policy_tables_block_legacy_even_with_zero_denials(self):
        guarded,owner,portal,ingress=self.opted()
        self.assertIs(type(guarded),LocalDenyCore)
        self.assertEqual(0,guarded._local_revision(self._db_read(guarded)))
        with self.assertRaisesRegex(Denied,'R7_LEGACY_CORE_LOCAL_DENY_BYPASS_FORBIDDEN'):
            guard(self.root)
        with self.assertRaisesRegex(Denied,'R7_LEGACY_CORE_LOCAL_DENY_BYPASS_FORBIDDEN'):
            self.legacy()
        with guarded._db() as db:
            self.assertEqual('READY',db.execute(
                'SELECT gate FROM owner_local_policy_meta').fetchone()[0])
            self.assertEqual(0,db.execute(
                'SELECT COUNT(*) FROM owner_local_policy_events').fetchone()[0])

    def test_local_deny_and_revision_survive_refused_legacy_start(self):
        guarded,_,_,_=self.opted()
        key=('repo-sonar-read-proposal-actor','sonarcloud','accept_issue','ISSUE-1')
        with guarded._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute("INSERT INTO owner_local_denials VALUES(?,?,?,?,'DENY')",key)
            db.execute("UPDATE owner_local_policy_meta SET revision=revision+1")
        with self.assertRaises(Denied):
            self.legacy()
        restarted,_,_,_=self.opted()
        self.assertEqual('DENY',restarted._policy(key[0],dict(
            service=key[1],operation=key[2],target=key[3])))
        self.assertEqual(1,restarted._local_revision(self._db_read(restarted)))

    def test_partial_local_table_name_blocks_even_without_metadata(self):
        path=self.root/'approvals.sqlite'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE owner_local_denials(id TEXT)')
        with self.assertRaisesRegex(Denied,'R7_LEGACY_CORE_LOCAL_DENY_BYPASS_FORBIDDEN'):
            guard(self.root)
        with self.assertRaises(Denied):
            self.legacy()

    def test_corrupted_database_is_not_treated_as_legacy_safe(self):
        self.legacy()  # Install the legitimate R7 private state marker first.
        path=self.root/'approvals.sqlite'
        path.write_bytes(b'invalid-sqlite-state')
        with self.assertRaisesRegex(Denied,'R7_LOCAL_POLICY_DB_UNVERIFIABLE'):
            guard(self.root)
        with self.assertRaisesRegex(Denied,'R7_LOCAL_POLICY_DB_UNVERIFIABLE'):
            self.legacy()
        self.assertEqual(b'invalid-sqlite-state',path.read_bytes())

    def test_symlink_database_is_not_followed_or_replaced(self):
        external=self.root/'other.db'
        with sqlite3.connect(external) as db:
            db.execute('CREATE TABLE owner_local_policy_meta(revision INTEGER)')
        path=self.root/'approvals.sqlite'
        path.symlink_to(external)
        with self.assertRaisesRegex(Denied,'R7_LOCAL_POLICY_DB_UNVERIFIABLE'):
            guard(self.root)
        self.assertTrue(path.is_symlink())
        with sqlite3.connect(external) as db:
            self.assertIsNotNone(db.execute(
                "SELECT name FROM sqlite_master WHERE name='owner_local_policy_meta'").fetchone())

    def test_directory_instead_of_db_is_denied(self):
        (self.root/'approvals.sqlite').mkdir()
        with self.assertRaisesRegex(Denied,'R7_LOCAL_POLICY_DB_UNVERIFIABLE'):
            guard(self.root)

    def test_unrelated_schema_does_not_trigger_false_legacy_block(self):
        path=self.root/'approvals.sqlite'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE unrelated_work(id TEXT)')
        original=path.read_bytes()
        self.assertTrue(guard(self.root)['legacyCoreAllowed'])
        self.assertEqual(original,path.read_bytes())

    def test_guard_is_read_only_and_has_no_recovery_api(self):
        for name in ('clear','recover','migrate','delete','reset','apply',
                     'reconcile','retry','activate'):
            self.assertFalse(hasattr(guard,name))
        self.assertTrue(guard(self.root)['legacyCoreAllowed'])

    def _db_read(self, core):
        context=core._db()
        db=context.__enter__()
        self.addCleanup(context.__exit__,None,None,None)
        return db


if __name__=='__main__':
    unittest.main()
