"""Backup/restore of PNG-MVP Gateway state alongside the legacy native layout."""
import hashlib
import os
from pathlib import Path
import sqlite3
import unittest

from test_orphaned_worker_claim_release import OrphanedClaimStateTests, H, IDENT

PNG = b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\x0dIHDR' + b'\x00' * 17
MEDIA_ID = '33333333-3333-4333-8333-333333333333'


class VisualMediaReleaseTests(unittest.TestCase):
    def setUp(self):
        # Reuse the existing orphaned-CLAIMED and UNCERTAIN fixture so every
        # clone still checks the accepted state-preservation guarantees.
        OrphanedClaimStateTests.setUp(self)
        self.folder = self.source/'private'/H.VISUAL_MEDIA_DIR
        self.folder.mkdir(mode=0o700)
        with sqlite3.connect(self.source/'private/native-git/workflow.sqlite') as db:
            db.execute('CREATE TABLE visual_media(request_id TEXT,actor TEXT,repo TEXT,'
                       'run_id TEXT,idx INTEGER,sha TEXT,size INTEGER,name TEXT,'
                       'PRIMARY KEY(request_id,idx))')
        self.digest = hashlib.sha256(PNG).hexdigest()
        self.filename = MEDIA_ID+'-0-'+self.digest+'.png'
        self.asset = self.folder/self.filename

    def insert(self):
        self.asset.write_bytes(PNG)
        self.asset.chmod(0o600)
        with sqlite3.connect(self.source/'private/native-git/workflow.sqlite') as db:
            db.execute('INSERT INTO visual_media VALUES (?,?,?,?,?,?,?,?)',
                       (MEDIA_ID,'agent','visual-workspace','run-001',0,self.digest,len(PNG),'Preview'))

    def inspect(self):
        return H.inspect_state(self.source,**self.kw,**self.good,
                               require_exact_uncertain=True,require_exact_claimed=True)

    def test_empty_visual_directory_and_table_survive_clone(self):
        before=self.inspect()
        self.assertEqual(before['summary']['native']['preservedClaimedIds'],[IDENT])
        result=H.clone_state(self.source,self.target,**self.kw,**self.good)
        self.assertEqual(result,before)
        self.assertTrue((self.target/'private'/H.VISUAL_MEDIA_DIR).is_dir())
        with sqlite3.connect(self.target/'private/native-git/workflow.sqlite') as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM visual_media').fetchone()[0],0)

    def test_registered_png_and_issue_receipt_survive_byte_exactly(self):
        self.insert()
        # GitHub receipt persistence now also tracks run reservations.
        with sqlite3.connect(self.source/'private/github-receipts.sqlite') as db:
            db.execute('CREATE TABLE visual_reviews(id TEXT PRIMARY KEY,repository TEXT,run_id TEXT,'
                       'issue_number INTEGER,uploads TEXT NOT NULL,UNIQUE(repository,run_id))')
            db.execute('INSERT INTO visual_reviews VALUES(?,?,?,?,?)',
                       (MEDIA_ID,'visual-workspace','run-001',42,'{}'))
        before=self.inspect()
        copied=H.clone_state(self.source,self.target,**self.kw,**self.good)
        self.assertEqual(before,copied)
        self.assertIn(H.VISUAL_MEDIA_DIR+'/'+self.filename,before['sha256'])
        self.assertEqual((self.target/'private'/H.VISUAL_MEDIA_DIR/self.filename).read_bytes(),PNG)
        self.assertEqual((self.target/'private/github-receipts.sqlite').read_bytes(),
                         (self.source/'private/github-receipts.sqlite').read_bytes())
        with sqlite3.connect(self.target/'private/github-receipts.sqlite') as db:
            self.assertEqual(db.execute('SELECT issue_number FROM visual_reviews').fetchone()[0],42)

    def test_unknown_file_is_not_silently_cloned(self):
        (self.folder/'unreviewed.txt').write_bytes(b'unknown')
        with self.assertRaisesRegex(RuntimeError,'PILOT_VISUAL_MEDIA_FILENAME_INVALID'):
            self.inspect()
        self.assertEqual(list(self.target.iterdir()),[])

    def test_unregistered_png_is_rejected(self):
        self.asset.write_bytes(PNG);self.asset.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError,'PILOT_VISUAL_MEDIA_UNREGISTERED_FILE'):
            self.inspect()

    def test_digest_change_is_rejected(self):
        self.insert()
        self.asset.write_bytes(PNG+b'changed')
        with self.assertRaisesRegex(RuntimeError,'PILOT_VISUAL_MEDIA_DIGEST_MISMATCH'):
            self.inspect()

    def test_wrong_row_binding_and_symlink_are_rejected(self):
        self.insert()
        with sqlite3.connect(self.source/'private/native-git/workflow.sqlite') as db:
            db.execute("UPDATE visual_media SET repo='other' WHERE request_id=?",(MEDIA_ID,))
        with self.assertRaisesRegex(RuntimeError,'PILOT_VISUAL_MEDIA_ROW_INVALID'):
            self.inspect()
        with sqlite3.connect(self.source/'private/native-git/workflow.sqlite') as db:
            db.execute("UPDATE visual_media SET repo='visual-workspace' WHERE request_id=?",(MEDIA_ID,))
        self.asset.unlink()
        other=self.root/'other';other.write_bytes(PNG);other.chmod(0o600)
        self.asset.symlink_to(other)
        with self.assertRaisesRegex(RuntimeError,'PILOT_SOURCE_FILE_INVALID'):
            self.inspect()

    def test_legacy_fixture_without_visual_media_remains_admissible(self):
        self.folder.rmdir()
        with sqlite3.connect(self.source/'private/native-git/workflow.sqlite') as db:
            db.execute('DROP TABLE visual_media')
        self.assertEqual(self.inspect()['summary']['native']['preservedClaimedIds'],[IDENT])

    def test_directory_table_mismatch_denied(self):
        with sqlite3.connect(self.source/'private/native-git/workflow.sqlite') as db:
            db.execute('DROP TABLE visual_media')
        with self.assertRaisesRegex(RuntimeError,'PILOT_NATIVE_SCHEMA_UNKNOWN'):
            self.inspect()

if __name__=='__main__':unittest.main()
