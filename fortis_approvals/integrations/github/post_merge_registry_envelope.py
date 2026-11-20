"""Offline P5 post-merge evidence *candidate* structure, NOT a Gateway method.

No transport, signing key, permission, collector, live policy or Registry WRITE.
Fields are untrusted assertions until a separate owner-reviewed typed collector
can attest immutable source provenance. This module NEVER returns ADMISSIBLE.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,99}\Z")
_REQUEST_ID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


class EvidenceEnvelopeError(ValueError):
    """Fail closed; never interpret as an empty queue or ready release."""


def need(condition, code):
    if not condition:
        raise EvidenceEnvelopeError(code)


def exact(obj, keys, code):
    need(type(obj) is dict and set(obj) == set(keys), code)
    return obj


def text(value, maxlen=256):
    return type(value) is str and bool(value) and value.strip() == value and len(value) <= maxlen


def sha(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def digest(value):
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def utc(value):
    if not text(value, 60):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _body_proof(proof, head_sha, merged_at):
    exact(proof, ('headSha', 'bodySha256', 'captureRef', 'reviewedAt', 'reviewCutoffRef'),
          'REVIEWED_BODY_FIELDS_INVALID')
    need(proof['headSha'] == head_sha and digest(proof['bodySha256']) and
         text(proof['captureRef'], 512) and text(proof['reviewCutoffRef'], 512),
         'REVIEWED_BODY_BINDING_INVALID')
    reviewed_at = utc(proof['reviewedAt'])
    need(reviewed_at is not None and reviewed_at <= merged_at,
         'REVIEW_CUTOFF_NOT_PROVEN')


def _paths_proof(paths):
    exact(paths, ('sha256', 'count', 'complete', 'renamePolicy', 'sourceRef'),
          'CHANGED_PATH_FIELDS_INVALID')
    need(digest(paths['sha256']) and type(paths['count']) is int and
         0 <= paths['count'] <= 10000 and paths['complete'] is True and
         paths['renamePolicy'] == 'old-and-new' and text(paths['sourceRef'], 512),
         'CHANGED_PATH_COVERAGE_INVALID')


def _ci_proof(ci, head_sha):
    exact(ci, ('headSha', 'policySha256', 'requiredChecks', 'checkRuns',
               'complete', 'sourceRef'), 'CI_FIELDS_INVALID')
    need(ci['headSha'] == head_sha and digest(ci['policySha256']) and
         ci['complete'] is True and text(ci['sourceRef'], 512),
         'CI_HEAD_POLICY_MISMATCH')
    names = ci['requiredChecks']
    runs = ci['checkRuns']
    need(type(names) is list and bool(names) and len(names) <= 100 and
         all(text(n, 128) for n in names) and names == sorted(set(names)) and
         type(runs) is list and 0 < len(runs) <= 100, 'CI_REQUIRED_SET_INVALID')
    observed = set()
    for run in runs:
        exact(run, ('name', 'headSha', 'runId', 'attempt', 'conclusion', 'sourceRef'),
              'CI_RUN_FIELDS_INVALID')
        need(run['name'] in names and run['headSha'] == head_sha and
             type(run['runId']) is int and run['runId'] > 0 and
             type(run['attempt']) is int and 0 < run['attempt'] <= 100 and
             run['conclusion'] == 'success' and text(run['sourceRef'], 512),
             'CI_RUN_NOT_EXACT_SUCCESS')
        need(run['name'] not in observed, 'CI_ATTEMPT_AMBIGUOUS')
        observed.add(run['name'])
    need(observed == set(names), 'CI_REQUIRED_CHECK_MISSING')


def _pr(pr, selected_main, known_numbers):
    exact(pr, ('number', 'headSha', 'mergeSha', 'mergedAt', 'mergedMainSha',
               'reviewedBody', 'changedPaths', 'ci', 'mergeLineageRef',
               'ancestryRef', 'releaseImpactSha256'), 'PR_FIELDS_INVALID')
    n = pr['number']
    need(type(n) is int and 0 < n <= 1000000 and n not in known_numbers,
         'PR_NUMBER_DUPLICATE_OR_INVALID')
    known_numbers.add(n)
    need(sha(pr['headSha']) and sha(pr['mergeSha']) and
         pr['mergedMainSha'] == selected_main and
         text(pr['mergeLineageRef'], 512) and text(pr['ancestryRef'], 512) and
         digest(pr['releaseImpactSha256']), 'MERGE_LINEAGE_CLAIM_INVALID')
    merged_at = utc(pr['mergedAt'])
    need(merged_at is not None, 'MERGED_AT_INVALID')
    _body_proof(pr['reviewedBody'], pr['headSha'], merged_at)
    _paths_proof(pr['changedPaths'])
    _ci_proof(pr['ci'], pr['headSha'])
    # A field named ancestryRef is ONLY a reference to a claim. It does not
    # prove actual Git parentage and must never be promoted by this function.


def inspect_candidate(envelope):
    """Strict offline structure validation; output is ALWAYS not-authorized.

    A complete-looking fixture is still self-attested. The future reviewed
    collector must independently verify all PR/CI/catalog/source identities.
    """
    exact(envelope, ('schemaVersion', 'repository', 'selectedMainSha',
                     'collectorClaim', 'catalog', 'mergedPullRequests',
                     'dependencyClosure', 'coverage'), 'ENVELOPE_FIELDS_INVALID')
    need(type(envelope['schemaVersion']) is int and envelope['schemaVersion'] == 1,
         'SCHEMA_VERSION_UNSUPPORTED')
    repo = envelope['repository']
    need(type(repo) is str and _REPO.fullmatch(repo) is not None and
         '..' not in repo, 'REPOSITORY_INVALID')
    main = envelope['selectedMainSha']
    need(sha(main), 'MAIN_SHA_INVALID')
    claim = exact(envelope['collectorClaim'], ('requestId', 'actor', 'capturedAt', 'sourceRef'),
                  'COLLECTOR_CLAIM_INVALID')
    need(type(claim['requestId']) is str and _REQUEST_ID.fullmatch(claim['requestId']) and
         text(claim['actor'], 128) and text(claim['sourceRef'], 512) and
         utc(claim['capturedAt']) is not None, 'COLLECTOR_IDENTITY_INVALID')
    catalog = exact(envelope['catalog'], ('repository', 'path', 'commitSha',
                                          'blobSha256', 'contentSha256',
                                          'snapshotRef', 'componentMapSha256'),
                    'CATALOG_FIELDS_INVALID')
    need(catalog['repository'] == repo and catalog['path'] == 'release/targets.yaml'
         and sha(catalog['commitSha']) and digest(catalog['blobSha256']) and
         digest(catalog['contentSha256']) and
         digest(catalog['componentMapSha256']) and
         text(catalog['snapshotRef'], 512), 'CATALOG_BINDING_INVALID')
    coverage = exact(envelope['coverage'], ('reviewedBody', 'mergeLineage',
                                            'changedPaths', 'catalog', 'ci',
                                            'dependencies'), 'COVERAGE_FIELDS_INVALID')
    need(all(coverage[k] is True for k in coverage), 'COVERAGE_CLAIM_INCOMPLETE')
    prs = envelope['mergedPullRequests']
    need(type(prs) is list and 0 < len(prs) <= 100, 'MERGED_PR_LIST_INVALID')
    seen = set()
    captured_at = utc(claim['capturedAt'])
    for pr in prs:
        _pr(pr, main, seen)
        need(captured_at >= utc(pr['mergedAt']), 'POST_MERGE_CAPTURE_BEFORE_MERGE')
    need([pr['number'] for pr in prs] == sorted(seen),
         'MERGED_PR_ORDER_INVALID')
    dependencies = exact(envelope['dependencyClosure'],
                         ('edges', 'digest', 'sourceRef', 'complete'),
                         'DEPENDENCY_FIELDS_INVALID')
    need(dependencies['complete'] is True and digest(dependencies['digest']) and
         text(dependencies['sourceRef'], 512) and type(dependencies['edges']) is list and
         len(dependencies['edges']) <= 256, 'DEPENDENCY_CLOSURE_INVALID')
    pairs = []
    for edge in dependencies['edges']:
        exact(edge, ('repository', 'target', 'sourceSha'), 'DEPENDENCY_EDGE_INVALID')
        need(type(edge['repository']) is str and _REPO.fullmatch(edge['repository']) and
             type(edge['target']) is str and _NAME.fullmatch(edge['target']) and
             sha(edge['sourceSha']), 'DEPENDENCY_EDGE_INVALID')
        pairs.append((edge['repository'], edge['target'], edge['sourceSha']))
    need(pairs == sorted(set(pairs)), 'DEPENDENCY_DUPLICATE_OR_UNSORTED')
    try:
        normalized = json.dumps(envelope, sort_keys=True, separators=(',', ':'),
                                ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise EvidenceEnvelopeError('ENVELOPE_CANONICAL_INVALID') from exc
    need(len(normalized) <= 2_000_000, 'ENVELOPE_TOO_LARGE')
    return {
        'result': 'SOURCE_CANDIDATE_ONLY',
        'schemaVersion': 1,
        'repository': repo,
        'selectedMainSha': main,
        'claimedPrCount': len(prs),
        'candidateDigest': hashlib.sha256(normalized).hexdigest(),
        'evidenceVerified': False,
        'admissionAllowed': False,
        'deploymentAllowed': False,
        'missingTrustedAttestations': [
            'ACTOR_AND_COLLECTOR_AUTHENTICATION',
            'REVIEW_CUTOFF_IMMUTABILITY',
            'PROVIDER_MERGE_ANCESTRY',
            'COMPLETE_CHANGED_PATHS',
            'PINNED_CATALOG_CONTENT',
            'REQUIRED_CI_ATTEMPT_POLICY',
            'DEPENDENCY_CLOSURE_PROVENANCE',
            'PROTECTED_INTEGRITY_AND_RECOVERY',
        ],
    }
