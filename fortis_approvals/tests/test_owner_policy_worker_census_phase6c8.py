"""Phase 6C.8 read-only owner-declared worker census consistency tests.

The fixture is OWNER-SUPPLIED data, not real process discovery, a signature,
image attestation, source trust or production deployment permission.
"""
from copy import deepcopy
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.extensions.owner_policy_worker_census_phase6c8 import (
    assess_owner_worker_census as assess)


def fixture():
    expected={
        'schemaVersion':1,'observedAt':200,'maxAgeSeconds':10,
        'requiredRoles':['machine-ingress','native-broker','owner-http'],
        'expectedProcesses':[
            {'pid':101,'startTicks':10001,'roles':['machine-ingress','native-broker']},
            {'pid':202,'startTicks':20002,'roles':['owner-http']}],
        'sourceDigest':'a'*64,'credentialGenerationDigest':'b'*64,
        'grantDigest':'c'*64,'policyVersion':'r7|owner-local-deny:7',
        'revision':7,
        'database':{'path':'/owner-state/approvals.sqlite','device':19,'inode':5501},
        'enumerationComplete':True,
    }
    records=[]
    for worker in expected['expectedProcesses']:
        records.append({**deepcopy(worker),'coreType':'LocalDenyCore',
                        'sourceDigest':expected['sourceDigest'],
                        'credentialGenerationDigest':expected['credentialGenerationDigest'],
                        'grantDigest':expected['grantDigest'],
                        'policyVersion':expected['policyVersion'],
                        'revision':expected['revision'],
                        'database':deepcopy(expected['database']),
                        'observedAt':198})
    return expected,records


class WorkerCensusClassifierTests(unittest.TestCase):
    def classify(self,change=None,record_change=None):
        expected,records=fixture()
        if change:
            change(expected)
        if record_change:
            record_change(records)
        return assess(expected,records)

    def test_consistent_declared_workers_never_authorizes_activation(self):
        result=self.classify()
        self.assertTrue(result['consistentDeclaredSamples'])
        self.assertEqual([],result['blockers'])
        self.assertEqual((2,2),(
            result['expectedProcesses'],result['observedProcesses']))
        for key in ('ownerHostAttested','processEnumerationIndependentlyVerified',
                    'rollbackProtected','runtimeIntegrated','canDeploy','canApplyPolicy'):
            self.assertIs(result[key],False)

    def test_two_replicas_of_one_role_allowed_when_both_enumerated(self):
        expected,rows=fixture()
        replica=deepcopy(expected['expectedProcesses'][0])
        replica.update(pid=303,startTicks=30003,roles=['machine-ingress'])
        expected['expectedProcesses'].append(replica)
        observed=deepcopy(rows[0])
        observed.update(pid=303,startTicks=30003,roles=['machine-ingress'])
        rows.append(observed)
        result=assess(expected,rows)
        self.assertTrue(result['consistentDeclaredSamples'])
        self.assertFalse(result['canDeploy'])

    def test_missing_worker_is_release_stop(self):
        result=self.classify(record_change=lambda r:r.pop())
        self.assertFalse(result['consistentDeclaredSamples'])
        self.assertIn('MISSING_EXPECTED_PROCESS',result['blockers'])
        self.assertIn('PROCESS_SET_MISMATCH',result['blockers'])

    def test_unknown_worker_is_release_stop_even_if_known_workers_match(self):
        def change(rows):
            extra=deepcopy(rows[0])
            extra.update(pid=303,startTicks=30003)
            rows.append(extra)
        result=self.classify(record_change=change)
        self.assertIn('UNKNOWN_RUNNING_PROCESS',result['blockers'])
        self.assertIn('PROCESS_SET_MISMATCH',result['blockers'])

    def test_legacy_incident_core_blocks_consistency(self):
        result=self.classify(record_change=lambda r:r[0].update(
            coreType='IncidentCore'))
        self.assertEqual(['UNGUARDED_CORE_DETECTED'],result['blockers'])

    def test_split_db_path_inode_or_device_is_refused(self):
        for changed in ({'path':'/different/approvals.sqlite'},
                        {'inode':5502},{'device':20}):
            with self.subTest(changed=changed):
                result=self.classify(record_change=lambda r:r[0][
                    'database'].update(changed))
                self.assertIn('SQLITE_STATE_IDENTITY_MISMATCH',result['blockers'])

    def test_mismatched_source_credentials_or_actor_grants_are_refused(self):
        for key,value,blocker in (
            ('sourceDigest','d'*64,'INSTALLED_SOURCE_MISMATCH'),
            ('credentialGenerationDigest','e'*64,'CREDENTIAL_GENERATION_MISMATCH'),
            ('grantDigest','f'*64,'ACTOR_GRANTS_MISMATCH')):
            with self.subTest(key=key):
                result=self.classify(record_change=lambda r:r[0].update(
                    {key:value}))
                self.assertIn(blocker,result['blockers'])
                self.assertFalse(result['canDeploy'])

    def test_revision_or_version_divergence_is_not_allowed(self):
        for key,value in (('revision',6),('policyVersion','old|owner-local-deny:6')):
            with self.subTest(key=key):
                result=self.classify(record_change=lambda r:r[0].update(
                    {key:value}))
                self.assertEqual(['POLICY_REVISION_MISMATCH'],result['blockers'])

    def test_expired_or_future_samples_are_rejected(self):
        for sample_time in (189,201):
            with self.subTest(sample_time=sample_time):
                result=self.classify(record_change=lambda r:r[0].update(
                    observedAt=sample_time))
                self.assertIn('STALE_OR_FUTURE_PROCESS_SAMPLE',result['blockers'])
        result=self.classify(record_change=lambda r:r[0].update(
            observedAt=190))
        self.assertTrue(result['consistentDeclaredSamples'])

    def test_pid_reuse_and_changed_roles_rejected(self):
        for change in ({'startTicks':10002},{'roles':['owner-http']}):
            with self.subTest(change=change):
                result=self.classify(record_change=lambda r:r[0].update(change))
                self.assertIn('PROCESS_IDENTITY_OR_ROLE_MISMATCH',result['blockers'])

    def test_unconfirmed_enumeration_holds_even_with_matching_records(self):
        result=self.classify(change=lambda e:e.update(enumerationComplete=False))
        self.assertEqual(['EXTERNAL_ENUMERATION_NOT_CONFIRMED'],result['blockers'])
        self.assertFalse(result['consistentDeclaredSamples'])

    def test_duplicate_process_or_role_in_expected_schema_fails_closed(self):
        for change in (
            lambda e:e['expectedProcesses'].append(deepcopy(e['expectedProcesses'][0])),
            lambda e:e['expectedProcesses'][1].update(roles=['machine-ingress']),
            lambda e:e.update(requiredRoles=['machine-ingress','owner-http']),
            lambda e:e.update(expectedProcesses=[])):
            with self.subTest(change=change),self.assertRaises(Denied):
                self.classify(change=change)

    def test_duplicate_observed_pid_is_rejected_not_lost_in_dict(self):
        def duplicate(rows):
            rows.append(deepcopy(rows[0]))
        with self.assertRaisesRegex(Denied,'OWNER_WORKER_CENSUS_DUPLICATE_PID'):
            self.classify(record_change=duplicate)

    def test_unknown_role_schema_fails_closed(self):
        with self.assertRaises(Denied):
            self.classify(record_change=lambda r:r[0].update(roles=[
                'machine-ingress','untrusted-owner']))
        with self.assertRaises(Denied):
            self.classify(change=lambda e:e.update(requiredRoles=[
                'machine-ingress','unknown-owner']))

    def test_unknown_fields_boolean_as_number_and_untrusted_digest_rejected(self):
        for change in (
            lambda e:e.update(canDeploy=True),
            lambda e:e.update(schemaVersion=True),
            lambda e:e.update(revision=False),
            lambda e:e.update(sourceDigest='0'*63),
            lambda e:e.update(policyVersion='old-unguarded-core'),
            lambda e:e.update(policyVersion='r7|owner-local-deny:6'),
            lambda e:e['database'].update(path='/owner-state/evil\nfile'),
            lambda e:e.update(maxAgeSeconds=61),
            lambda e:e.update(observedAt=-1),
            lambda e:e['database'].update(path='/owner-state/../old.sqlite'),
            lambda e:e['database'].update(inode=True)):
            with self.subTest(change=change),self.assertRaises(Denied):
                self.classify(change=change)

    def test_unknown_observation_fields_or_bad_pid_rejected(self):
        for mutate in (
            lambda rows:rows[0].update(ownerApproved=True),
            lambda rows:rows[0].update(pid=True),
            lambda rows:rows[0].update(observedAt='200'),
            lambda rows:rows[0].update(database={'path':'/tmp/a','inode':12}),
            lambda rows:rows[0].update(sourceDigest='bogus')):
            with self.subTest(mutate=mutate),self.assertRaises(Denied):
                self.classify(record_change=mutate)

    def test_response_is_only_inert_comparison_no_credential_or_apply(self):
        expected,rows=fixture()
        result=assess(expected,rows)
        self.assertNotIn(expected['grantDigest'],str(result))
        self.assertNotIn(expected['credentialGenerationDigest'],str(result))
        self.assertNotIn(expected['sourceDigest'],str(result))
        for key in ('apply','execute','rollback','deploy','activate','authority'):
            self.assertNotIn(key,result)
        self.assertEqual('OWNER_WORKER_CENSUS_OFFLINE_COMPARISON_V1',result['kind'])


if __name__=='__main__':
    unittest.main()
