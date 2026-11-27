"""Offline successor schema and full companion audit with real Core fixtures."""
from shutil import copyfile
import sqlite3
import unittest

from fortis_approvals.core import Core, Denied
from fortis_approvals.extensions import composite_preservation as cp
from fortis_approvals.tests import test_composite_executor as fixture


class CompositePreservationTests(unittest.TestCase):
    setUp = fixture.CompositeExecutorTests.setUp
    make_core = fixture.CompositeExecutorTests.make_core
    payload = fixture.CompositeExecutorTests.payload
    submit = fixture.CompositeExecutorTests.submit
    approve = fixture.CompositeExecutorTests.approve

    def snapshot(self, core, read):
        db = sqlite3.connect(core.path.absolute().as_uri()+'?mode=ro', uri=True)
        try:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            return read(db)
        finally:
            db.close()

    def test_exact_legacy_schema_addition(self):
        old = Core(self.path.parent/'legacy.sqlite', adapters={}, policies={}, authenticator=self.auth)
        expected = self.snapshot(old, cp.legacy_schema_witness)
        with old._db() as db:
            db.execute('BEGIN IMMEDIATE')
            result = cp.install_checked(db, expected=expected)
        self.assertEqual(result['result'], 'COMPOSITE_SCHEMA_ADDED_ONLY')
        self.assertEqual(result['coreRowsDigest'], expected['coreRowsDigest'])
        self.assertNotEqual(result['afterSchemaDigest'], expected['schemaDigest'])
        self.assertEqual(self.snapshot(old, cp.inspect_companion)['parents'], 0)

    def test_readonly_projection_and_exact_apply_clone(self):
        old = Core(self.path.parent/'legacy.sqlite', adapters={}, policies={}, authenticator=self.auth)
        pin = self.snapshot(old, cp.legacy_schema_witness)
        prepared = self.path.parent/'prepared.sqlite'
        copyfile(old.path, prepared)
        with sqlite3.connect(prepared) as db:
            db.execute('BEGIN IMMEDIATE')
            cp.install_checked(db, expected=pin)
        with sqlite3.connect(prepared) as db:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            candidate = cp.digest(cp.inspect_companion(db))

        before = old.path.read_bytes()
        self.assertEqual(cp.project_staged_companion(old.path, expected_digest=candidate), pin)
        self.assertEqual(old.path.read_bytes(), before)
        clone = self.path.parent/'apply.sqlite'
        copyfile(old.path, clone)
        with self.assertRaisesRegex(Denied, 'PRESERVATION_PIN_CHANGED'):
            cp.prepare_staged_companion(clone, legacy=pin, expected_digest='0'*64)
        with sqlite3.connect(clone) as db:
            self.assertEqual(cp.journal._schema_rows(db), [])
        cp.prepare_staged_companion(clone, legacy=pin, expected_digest=candidate)
        cp.prepare_staged_companion(clone, legacy=pin, expected_digest=candidate)
        with sqlite3.connect(clone) as db:
            db.execute('CREATE INDEX drift ON requests(state)')
        with self.assertRaisesRegex(Denied, 'PRESERVATION_PIN_CHANGED'):
            cp.prepare_staged_companion(clone, legacy=pin, expected_digest=candidate)

    def test_scratch_projection_accepts_source_larger_than_old_memory_budget(self):
        old = Core(self.path.parent/'large-legacy.sqlite', adapters={}, policies={}, authenticator=self.auth)
        with old._db() as db:
            db.execute('CREATE TABLE retained_payload(value BLOB)')
            db.execute('INSERT INTO retained_payload VALUES(zeroblob(?))', (65 * 1024 * 1024,))
        pin = self.snapshot(old, cp.legacy_schema_witness)
        prepared = self.path.parent/'prepared-large.sqlite'
        copyfile(old.path, prepared)
        with sqlite3.connect(prepared) as db:
            db.execute('BEGIN IMMEDIATE')
            cp.install_checked(db, expected=pin)
        with sqlite3.connect(prepared) as db:
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            expected = cp.digest(cp.inspect_companion(db))
        scratch = self.path.parent/'scratch'
        scratch.mkdir(mode=0o700)

        with self.assertRaisesRegex(Denied, 'PRESERVATION_STATE_LIMIT sourceBytes='):
            cp.project_staged_companion(old.path, expected_digest=expected)
        self.assertEqual(cp.project_staged_companion(old.path, expected_digest=expected,
                                                     scratch_root=scratch), pin)
        self.assertEqual(list(scratch.iterdir()), [])
        with sqlite3.connect(old.path) as db:
            self.assertEqual(cp.journal._schema_rows(db), [])

    def test_drifted_schema_pin_refused_without_install(self):
        old = Core(self.path.parent/'legacy.sqlite', adapters={}, policies={}, authenticator=self.auth)
        expected = self.snapshot(old, cp.legacy_schema_witness)
        with old._db() as db:
            db.execute('CREATE INDEX unexpected ON requests(state)')
        with self.assertRaises(Denied):
            with old._db() as db:
                db.execute('BEGIN IMMEDIATE')
                cp.install_checked(db, expected=expected)
        with old._db() as db:
            self.assertEqual(cp.journal._schema_rows(db), [])

    def test_completed_parent_receipt_and_event_coverage(self):
        view = self.submit()
        self.assertEqual(self.approve(view)['state'], 'EXECUTED')
        result = self.snapshot(self.core, cp.inspect_companion)
        self.assertEqual(result['parents'], 1)
        self.assertEqual(result['events']['count'], 4)
        self.assertEqual(result['parentStates'], {'EXECUTED': 1})
        self.assertEqual(result, self.snapshot(self.core, cp.inspect_companion))

    def test_missing_instance_rejected(self):
        view = self.submit()
        with self.core._db() as db:
            db.execute('DELETE FROM composite_instances WHERE parent_id=?', (view['requestId'],))
        with self.assertRaises(Denied):
            self.snapshot(self.core, cp.inspect_companion)

    def test_orphan_event_rejected(self):
        view = self.submit()
        self.approve(view)
        with self.core._db() as db:
            db.execute("UPDATE composite_step_events SET parent_id='missing'")
        with self.assertRaises(Denied):
            self.snapshot(self.core, cp.inspect_companion)

    def test_parent_receipt_corruption_rejected(self):
        view = self.submit()
        self.approve(view)
        with self.core._db() as db:
            db.execute("UPDATE requests SET result='{}' WHERE id=?", (view['requestId'],))
        with self.assertRaisesRegex(Denied, 'PARENT_RECEIPT'):
            self.snapshot(self.core, cp.inspect_companion)

    def test_no_write_snapshot(self):
        with self.core._db() as db:
            db.execute('BEGIN')
            with self.assertRaises(Denied):
                cp.inspect_companion(db)


if __name__ == '__main__':
    unittest.main()
