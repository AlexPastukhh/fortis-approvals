"""Nonempty synthetic state is preserved, and writes stay blocked until release."""
import importlib.util
import base64
import hashlib
import subprocess
import sys
import io
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile

DEPLOY = Path(__file__).resolve().parents[1] / 'deploy'
def module(name):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
exporter = module('snapshot_smoke_locked')
verifier = module('verify_smoke_backup')


class SmokeLockedBackupTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='r3-nonempty-offline-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / 'private'
        self.state.mkdir(mode=0o700)
        (self.state / '.fortis-r7-unified-v1').write_bytes(b'fortis-r7-unified-v1\n')
        with sqlite3.connect(self.state / 'approvals.sqlite') as db:
            db.executescript("CREATE TABLE requests(state TEXT); CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,value TEXT); INSERT INTO requests VALUES ('PENDING'); INSERT INTO events(value) VALUES ('created');")
        with sqlite3.connect(self.state / 'owner.sqlite') as db:
            db.executescript('CREATE TABLE config(setting TEXT,value TEXT); CREATE TABLE credentials(active INTEGER,data BLOB); CREATE TABLE invitations(value TEXT);')
            db.executemany('INSERT INTO config VALUES (?,?)', [('origin','http://localhost:19103'),('rpId','localhost'),('owner','owner')])
        with sqlite3.connect(self.state / 'sonar-receipts.sqlite') as db:
            db.execute('CREATE TABLE receipts(value TEXT)')
        for p in self.state.iterdir():
            p.chmod(0o600)

    def locked(self):
        return exporter.locked_snapshot(self.state, uid=os.geteuid(), gid=os.getegid())

    def extract(self, payload):
        target = self.root / 'backup'
        target.mkdir()
        (target / 'snapshot.zip').write_bytes(payload)
        with zipfile.ZipFile(io.BytesIO(payload)) as z:
            self.assertIsNone(z.testzip())
            z.extractall(target)
        return target

    def test_snapshot_preserves_request_and_holds_read_locks_until_release(self):
        with self.locked() as (payload, manifest, connections):
            self.assertTrue(all(db.in_transaction for db in connections.values()))
            self.assertEqual(manifest['summary']['requestStates'], {'PENDING': 1})
            target = self.extract(payload)
            result = verifier.verify(target)
            self.assertEqual(result['summary']['requests'], 1)
            self.assertEqual(result['summary']['events'], 1)
            for name, statement in [('approvals.sqlite', "INSERT INTO requests VALUES ('PENDING')"),
                                    ('owner.sqlite', "INSERT INTO invitations VALUES ('new')"),
                                    ('sonar-receipts.sqlite', "INSERT INTO receipts VALUES ('new')")]:
                writer = sqlite3.connect(self.state / name, timeout=0.01)
                try:
                    with self.assertRaisesRegex(sqlite3.OperationalError, 'locked'):
                        writer.execute(statement)
                        writer.commit()
                    writer.rollback()
                finally:
                    writer.close()
        with sqlite3.connect(self.state / 'approvals.sqlite', timeout=0.1) as db:
            db.execute("INSERT INTO requests VALUES ('PENDING')")
        self.assertEqual(verifier.verify(target)['summary']['requests'], 1)

    def test_credentials_invitations_and_receipts_are_not_dropped(self):
        with sqlite3.connect(self.state / 'owner.sqlite') as db:
            db.execute('INSERT INTO credentials VALUES (?,?)', (1, b'synthetic public credential'))
            db.execute("INSERT INTO invitations VALUES ('synthetic invitation')")
        with sqlite3.connect(self.state / 'sonar-receipts.sqlite') as db:
            db.execute("INSERT INTO receipts VALUES ('synthetic receipt')")
        with self.locked() as (payload, _, _):
            result = verifier.verify(self.extract(payload))
            self.assertEqual(result['summary']['credentialsActive'], 1)
            self.assertEqual(result['summary']['invitationsTotal'], 1)
            self.assertEqual(result['summary']['receipts'], 1)
            self.assertTrue(result['allLogicalContentHashesMatch'])

    def test_stream_protocol_keeps_locks_after_export_and_releases_on_command(self):
        code = ("import runpy;ns=runpy.run_path(" + repr(str(DEPLOY / 'snapshot_smoke_locked.py')) + ");"
                + "ns['serve'](" + repr(str(self.state)) + ",uid=" + str(os.geteuid())
                + ",gid=" + str(os.getegid()) + ")")
        process = subprocess.Popen([sys.executable, '-B', '-u', '-c', code],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            header = process.stdout.readline().strip().split()
            self.assertEqual(header[0], 'FORTIS_R3_LOCKED_ZIP_V1')
            line = process.stdout.readline().strip()
            self.assertEqual(len(line), int(header[1]))
            payload = base64.b64decode(line, validate=True)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), header[2])
            self.assertEqual(verifier.verify(self.extract(payload))['summary']['requests'], 1)
            process.stdin.write('STATUS\n'); process.stdin.flush()
            ack = process.stdout.readline().strip().split()
            self.assertEqual(ack[0], 'R3_LOCKS_HELD')
            self.assertGreaterEqual(int(ack[1]), 60)
            process.stdin.write('RELEASE\n'); process.stdin.flush()
            self.assertEqual(process.stdout.readline().strip(), 'R3_LOCKS_RELEASED')
            process.wait(timeout=5)
            self.assertEqual(process.returncode, 0, process.stderr.read())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

    def test_corrupt_backup_is_rejected_before_stop_admission(self):
        with self.locked() as (payload, _, _):
            target = self.extract(payload)
            with (target / 'approvals.sqlite').open('ab') as f:
                f.write(b'corrupt')
            with self.assertRaisesRegex(RuntimeError, 'HASH_MISMATCH'):
                verifier.verify(target)
