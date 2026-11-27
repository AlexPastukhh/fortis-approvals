"""Isolated transition bindings and old-prefix preservation tests."""
import copy
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.integrations.registry_contracts import transition_contract as tc
from fortis_approvals.registry import functional_v1_journal as local
from fortis_approvals.registry.transition_preservation import (
    compare_legacy_prefix, legacy_prefix_witness,
)
from fortis_approvals.tests.test_registry_state_journal import sample, uid


def manifest():
    return {
        'schemaVersion': 1, 'kind': 'REGISTRY_286_SUCCESSOR_TRANSITION',
        'transitionId': uid(), 'repository': tc.REPOSITORY,
        'old': {
            'sourceSha': tc.BASE_SHA, 'catalogSha256': tc.BASE_CATALOG,
            'historicalGapDigest': 'a'*64,
            'historicalGapPrefixDigest': tc.GAP_PREFIX,
            'registry': {'schemaVersion': 3, 'instanceId': uid(),
                         'scopeDigest': 'b'*64, 'genesisDigest': 'c'*64,
                         'revision': 0, 'eventDigest': 'c'*64,
                         'cursorSha': 'd'*40, 'prefixDigest': 'e'*64},
            'capture': {'revision': 0, 'eventDigest': 'f'*64},
            'collector': {'schemaVersion': 1, 'instanceId': uid(), 'revision': 0, 'eventDigest': '1'*64},
            'policy': {'revision': 8, 'authorityDigest': '2'*64, 'historyDigest': '3'*64},
            'corePreservationDigest': '4'*64, 'protectedStateDigest': '5'*64,
        },
        'pr': {'number': 287, 'baseSha': tc.BASE_SHA, 'headSha': '6'*40,
               'treeSha': '7'*40, 'mergeMethod': 'merge', 'bodyDigest': '8'*64,
               'impactDigest': '9'*64, 'pathsDigest': 'a'*64, 'ciDigest': 'b'*64},
        'successor': {'registrySchemaVersion': 4, 'catalogSha256': 'c'*64,
                      'authorityDigest': 'd'*64, 'coreSchemaDigest': 'e'*64,
                      'validatorRevision': 'f'*40, 'actionRevision': '1'*40,
                      'migrationContractDigest': '2'*64},
        'recovery': {'primaryRecordDigest': '3'*64, 'backupRecordDigest': '4'*64,
                     'registryBackupDigest': '5'*64},
    }


def observation(m):
    p = m['pr']
    return {'repository': m['repository'], 'number': p['number'],
            'headSha': p['headSha'], 'mergeSha': '2'*40, 'mainSha': '2'*40,
            'parents': [tc.BASE_SHA, p['headSha']], 'treeSha': p['treeSha'],
            'catalogSha256': m['successor']['catalogSha256'],
            **{k: p[k] for k in ('bodyDigest', 'impactDigest', 'pathsDigest', 'ciDigest')}}


class TransitionBindings(unittest.TestCase):
    def test_exact_manifest_and_observation(self):
        m = manifest()
        o = observation(m)
        self.assertEqual(tc.validate_manifest(m), m)
        result = tc.bind_merge(m, o, expected_manifest_digest=tc.digest(m))
        self.assertEqual(result['result'], 'TRANSITION_BINDINGS_MATCH_ONLY')
        self.assertEqual(result['mergeSha'], o['mergeSha'])
        self.assertEqual(result['observationDigest'], tc.digest(o))
        self.assertNotIn('admissionAllowed', result)

    def test_old_state_binding_refuses_drift(self):
        m = manifest()
        old = copy.deepcopy(m['old'])
        pin = tc.digest(m)
        self.assertEqual(tc.bind_old_state(m, old, expected_manifest_digest=pin)['result'],
                         'TRANSITION_OLD_BINDINGS_MATCH_ONLY')
        old['registry']['prefixDigest'] = '8'*64
        with self.assertRaisesRegex(Denied, 'OLD_STATE_CHANGED'):
            tc.bind_old_state(m, old, expected_manifest_digest=pin)

    def test_mutated_manifest_against_original_pin(self):
        m = manifest()
        pin = tc.digest(m)
        m['successor']['authorityDigest'] = '8'*64
        with self.assertRaisesRegex(Denied, 'TRANSITION_MANIFEST_CHANGED'):
            tc.bind_merge(m, observation(m), expected_manifest_digest=pin)

    def test_strict_predecessor_and_version(self):
        for path, key, value in (
            ('old', 'sourceSha', 'a'*40),
            ('old', 'catalogSha256', 'a'*64),
            ('old', 'historicalGapPrefixDigest', 'b'*64),
            ('pr', 'baseSha', 'a'*40),
            ('pr', 'mergeMethod', 'squash'),
            ('pr', 'number', 286),
            ('successor', 'registrySchemaVersion', 3),
            ('successor', 'registrySchemaVersion', True),
        ):
            with self.subTest(path=path, key=key):
                m = manifest()
                m[path][key] = value
                with self.assertRaises(Denied):
                    tc.validate_manifest(m)

    def test_strict_fields_and_bounds(self):
        for path, key, value in (
            ('old', 'authority', 'ALLOW'),
            ('pr', 'headSha', 'wrong'),
            ('recovery', 'backupRecordDigest', None),
            ('old', 'capture', {'revision': 129, 'eventDigest': 'a'*64}),
            ('old', 'collector', {'schemaVersion': 1, 'instanceId': uid(), 'revision': True, 'eventDigest': 'a'*64}),
        ):
            m = manifest()
            m[path][key] = value
            with self.subTest(path=path, key=key), self.assertRaises(Denied):
                tc.validate_manifest(m)

    def test_exact_observed_merge_rejects_drift(self):
        m = manifest()
        pin = tc.digest(m)
        for key, value in (
            ('repository', 'Other/other'),
            ('number', 288),
            ('headSha', 'f'*40),
            ('mainSha', 'f'*40),
            ('mergeSha', tc.BASE_SHA),
            ('parents', [m['pr']['headSha'], tc.BASE_SHA]),
            ('parents', [tc.BASE_SHA]),
            ('treeSha', 'a'*40),
            ('catalogSha256', 'a'*64),
            ('bodyDigest', 'a'*64),
            ('impactDigest', 'a'*64),
            ('pathsDigest', 'f'*64),
            ('ciDigest', 'a'*64),
            ('ownerApproved', True),
        ):
            o = observation(m)
            o[key] = value
            with self.subTest(key=key), self.assertRaises(Denied):
                tc.bind_merge(m, o, expected_manifest_digest=pin)

    def test_manifest_validation_detaches_input(self):
        m = manifest()
        clean = tc.validate_manifest(m)
        m['old']['policy']['revision'] += 1
        self.assertEqual(clean['old']['policy']['revision'], 8)


class LegacyPrefixTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.scope = {'repository': local.REPOSITORY, 'enrollmentId': uid(),
                      'baselineSha': 'a'*40, 'baselineDigest': 'a'*64,
                      'catalogSha256': 'b'*64, 'bindingDigest': 'c'*64,
                      'policyReferenceDigest': 'd'*64}
        self.instance = uid()
        self.evidence = sample(self.scope)
        self.path = self.root / 'old.sqlite'
        self.state = local.FunctionalV1CandidateJournal.initialize(
            self.path, instance_id=self.instance, scope=self.scope,
            plan_reader=lambda _: copy.deepcopy(self.evidence))

    def append(self):
        return self.state.append_range(
            actor=local.PLANNER, operation_id=uid(),
            evidence_id=self.evidence['evidenceId'],
            evidence_digest=local._hash(self.evidence), expected_revision=0)

    def clone(self):
        path = self.root / 'clone.sqlite'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with sqlite3.connect(self.path.as_uri()+'?mode=ro', uri=True) as src:
            with sqlite3.connect(path) as dst:
                src.backup(dst)
                dst.execute('PRAGMA journal_mode=WAL')
        return local.FunctionalV1CandidateJournal(
            path, instance_id=self.instance, scope=self.scope,
            plan_reader=lambda _: self.fail('must not fetch evidence'))

    def test_genesis_witness(self):
        witness = legacy_prefix_witness(self.state)
        self.assertEqual(witness['revision'], 0)
        self.assertEqual(witness['genesisDigest'], witness['eventDigest'])
        self.assertEqual(witness['cursorSha'], self.scope['baselineSha'])
        self.assertEqual(witness['instanceId'], self.instance)

    def test_verified_clone_preserves_original_receipt(self):
        receipt = self.append()['receipt']
        expected = legacy_prefix_witness(self.state)
        clone = self.clone()
        self.assertEqual(compare_legacy_prefix(expected, legacy_prefix_witness(clone)),
                         'LEGACY_PREFIX_MATCH_ONLY')
        self.assertEqual(clone.operation(actor=local.PLANNER,
                                        operation_id=receipt['operationId'])['receipt'], receipt)

    def test_changed_valid_prefix_rejected(self):
        old = legacy_prefix_witness(self.state)
        self.append()
        with self.assertRaisesRegex(Denied, 'PREFIX_CHANGED'):
            compare_legacy_prefix(old, legacy_prefix_witness(self.state))

    def test_corrupt_clone_receipt_rejected(self):
        self.append()
        clone = self.clone()
        with sqlite3.connect(clone.path) as db:
            db.execute("UPDATE operations SET receipt='{}'")
        with self.assertRaises(Denied):
            legacy_prefix_witness(clone)
        self.assertEqual(legacy_prefix_witness(self.state)['revision'], 1)

    def test_unknown_schema_rejected(self):
        clone = self.clone()
        with sqlite3.connect(clone.path) as db:
            db.execute('PRAGMA user_version=4')
        with self.assertRaises(Denied):
            legacy_prefix_witness(clone)


if __name__ == '__main__':
    unittest.main()
