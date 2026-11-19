"""Trusted owner-portal bridge for WebAuthn REVIEW of an inactive policy draft.

No machine/AI ingress, no secret or store provisioning, no policy apply.
Only an operator-injected, already trusted PolicyDraftLedger can enable it.
"""
import uuid

from ..core import Denied, Stale
from .owner_policy_preview import preview_policy_change
from .owner_policy_draft_ledger import PolicyDraftLedger
from .owner_policy_change_challenge import OwnerPolicyChangeReview, PURPOSE


_CANDIDATE_KEYS = frozenset(('provider','operation','actor','target',
    'expectedConfiguredPolicy','desiredPolicy','expectedPolicyVersion'))


class OwnerPolicyReviewHTTP:
    """Owner-only bound ceremony facade. No HTTP processing occurs here."""

    def __init__(self, core, owner_auth, ledger):
        if type(ledger) is not PolicyDraftLedger:
            raise Denied('OWNER_POLICY_REVIEW_TRUSTED_LEDGER_REQUIRED')
        if core.owner_verifier is not owner_auth:
            raise Denied('OWNER_POLICY_REVIEW_VERIFIER_MISMATCH')
        self.core = core
        self.auth = owner_auth
        self.ledger = ledger
        self.review = OwnerPolicyChangeReview(owner_auth)

    def capabilities(self):
        snapshot = self.ledger.snapshot()
        if snapshot['policyVersion'] != self.core.policy_version:
            raise Stale('OWNER_POLICY_REVIEW_POLICY_VERSION_CHANGED')
        if (snapshot['kind'] != 'INACTIVE_POLICY_DRAFT_LEDGER' or
            snapshot['canApply'] is not False or
            snapshot['runtimeIntegration'] != 'NOT_CONNECTED'):
            raise Denied('OWNER_POLICY_REVIEW_ACTIVE_STORE_UNEXPECTED')
        return {'configured': True, 'kind': 'OWNER_POLICY_DRAFT_REVIEW_ONLY',
            'requiresStrongWebAuthn': True, 'canApply': False,
            'revision': snapshot['revision'], 'policyVersion': snapshot['policyVersion']}

    def _preview(self, candidate, extension_runtime):
        if type(candidate) is not dict or set(candidate) != _CANDIDATE_KEYS:
            raise Denied('OWNER_POLICY_REVIEW_CANDIDATE_SCHEMA')
        preview = preview_policy_change(self.core, extension_runtime, candidate)
        if not preview['changed']:
            raise Denied('OWNER_POLICY_REVIEW_NOOP')
        if preview['canApply'] is not False or preview['applyEnabled'] is not False:
            raise Denied('OWNER_POLICY_REVIEW_PREVIEW_NOT_INERT')
        snapshot = self.ledger.snapshot()
        if snapshot['policyVersion'] != self.core.policy_version:
            raise Stale('OWNER_POLICY_REVIEW_POLICY_VERSION_CHANGED')
        coord = (candidate['actor'],candidate['provider'],candidate['operation'],candidate['target'])
        rows = [row for row in snapshot['drafts'] if
            (row['actor'],row['provider'],row['operation'],row['target']) == coord]
        if len(rows) != 1:
            raise Denied('OWNER_POLICY_REVIEW_UNTRACKED_EXACT_GRANT')
        # Inactive draft must match the actual configured policy; changes in
        # a draft or live policy invalidate this review until refreshed.
        if (rows[0]['baselinePolicy'] != candidate['expectedConfiguredPolicy'] or
            rows[0]['draftPolicy'] != candidate['expectedConfiguredPolicy']):
            raise Stale('OWNER_POLICY_REVIEW_DRAFT_BASELINE_OR_RULE_CHANGED')
        return preview, snapshot

    def begin(self, session, csrf, candidate, extension_runtime):
        preview, snap = self._preview(candidate, extension_runtime)
        change = {'purpose': PURPOSE, 'requestId': str(uuid.uuid4()),
            'actor': candidate['actor'], 'provider': candidate['provider'],
            'operation': candidate['operation'], 'target': candidate['target'],
            'oldPolicy': candidate['expectedConfiguredPolicy'],
            'newPolicy': candidate['desiredPolicy'],
            'expectedRevision': snap['revision'],
            'expectedAuditHash': snap['auditHash'],
            'baselineDigest': snap['baselineDigest'],
            'sourceDigest': snap['sourceDigest'],
            'credentialGenerationDigest': snap['credentialGenerationDigest'],
            'policyVersion': snap['policyVersion'],
            'reasonCode': 'OWNER_DASHBOARD_REVIEW',
            'expiresAt': int(self.auth.clock()) + 90}
        started = self.review.begin_policy_change_review(session, csrf, change, self.ledger)
        return {**started, 'change': change,
                'previewFingerprint': preview['previewFingerprint'],
                'canApply': False, 'policyActivated': False}

    def finish(self, session, csrf, ceremony, response, change, extension_runtime):
        # Must consume challenge even when the supplied change was tampered.
        result = self.review.finish_policy_change_review(
            session, csrf, ceremony, response, change, self.ledger)
        candidate = {
            'provider': change['provider'], 'operation': change['operation'],
            'actor': change['actor'], 'target': change['target'],
            'expectedConfiguredPolicy': change['oldPolicy'],
            'desiredPolicy': change['newPolicy'],
            'expectedPolicyVersion': change['policyVersion']}
        preview, _ = self._preview(candidate, extension_runtime)
        return {**result, 'previewFingerprint': preview['previewFingerprint'],
                'canApply': False, 'policyActivated': False}
