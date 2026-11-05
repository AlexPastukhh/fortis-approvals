"""Observed r3 process and empty-state proof; synthetic databases only."""
from copy import deepcopy
import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

DEPLOY = Path(__file__).resolve().parents[1] / 'deploy'
def module(name):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
contract = module('smoke_tmpfs_contract')
helper = module('probe_smoke_state')


def fixture():
    return {'Id': contract.ID, 'Name': contract.NAME, 'Image': contract.IMAGE,
        'Config': {'User': '10001:10001', 'Entrypoint': ['/bin/sh'], 'Cmd': list(contract.CMD)},
        'State': {'Status': 'running'}, 'Mounts': [
            {'Type': 'volume', 'Destination': dest, 'Name': name, 'RW': False} for dest, name in contract.CREDS],
        'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'AutoRemove': False,
            'IpcMode': 'private', 'NetworkMode': 'bridge', 'Tmpfs': {'/state': 'rw,uid=10001,gid=10001'},
            'PortBindings': {'19103/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19203'}],
                             '19104/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19204'}]}}}


class SmokeTmpfsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='r3-empty-offline-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.root.chmod(0o700)
        (self.root / '.fortis-r7-unified-v1').write_bytes(b'fortis-r7-unified-v1\n')
        with sqlite3.connect(self.root / 'approvals.sqlite') as db:
            db.executescript('CREATE TABLE requests(value TEXT); CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT);')
        with sqlite3.connect(self.root / 'owner.sqlite') as db:
            db.executescript('CREATE TABLE config(setting TEXT,value TEXT); CREATE TABLE credentials(active INTEGER); CREATE TABLE invitations(value TEXT);')
            db.executemany('INSERT INTO config VALUES (?,?)', [('origin','http://localhost:19103'),('rpId','localhost'),('owner','owner')])
        with sqlite3.connect(self.root / 'sonar-receipts.sqlite') as db:
            db.execute('CREATE TABLE receipts(value TEXT)')
        for path in self.root.iterdir():
            path.chmod(0o600)

    def probe(self):
        result = helper.probe(self.root, uid=os.geteuid(), gid=os.getegid())
        # Admission enforces the real runtime identity; synthetic fixture adapts only the IDs.
        result.update(uid=10001, gid=10001)
        return result

    def test_empty_observed_tmpfs_is_admitted_without_changing_bytes(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        report = self.probe()
        self.assertTrue(report['empty'])
        self.assertEqual(contract.admit_empty_stop(fixture(), report)['admission'], 'PASS')
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_any_request_credential_invitation_or_receipt_blocks_stop(self):
        for name, table, values in [('approvals.sqlite','requests',('request',)),
                                   ('owner.sqlite','credentials',(1,)),
                                   ('owner.sqlite','invitations',('invitation',)),
                                   ('sonar-receipts.sqlite','receipts',('receipt',))]:
            with self.subTest(table=table):
                with sqlite3.connect(self.root / name) as db:
                    db.execute('INSERT INTO ' + table + ' VALUES (?)', values)
                report = self.probe()
                self.assertFalse(report['empty'])
                with self.assertRaisesRegex(RuntimeError, 'NOT_PROVEN_EMPTY'):
                    contract.admit_empty_stop(fixture(), report)
                with sqlite3.connect(self.root / name) as db:
                    db.execute('DELETE FROM ' + table)

    def test_tmpfs_and_exact_identity_cannot_be_substituted(self):
        for change in [lambda d: d.update(Id='a'*64), lambda d: d['HostConfig'].update(Tmpfs={}),
                       lambda d: d['HostConfig'].update(AutoRemove=True),
                       lambda d: d['Config'].update(Cmd=['something else']),
                       lambda d: d['Mounts'].append({'Type':'volume','Destination':'/state','Name':'fortis-r7-state','RW':True})]:
            data = deepcopy(fixture())
            change(data)
            with self.assertRaises(RuntimeError):
                contract.inspect_tmpfs(data)

    def test_sidecar_stops_probe_without_reading_inconsistent_state(self):
        (self.root / 'approvals.sqlite-wal').write_text('journal')
        with self.assertRaisesRegex(RuntimeError, 'UNEXPECTED_FILES'):
            self.probe()
