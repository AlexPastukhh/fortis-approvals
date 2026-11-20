"""P5 offline byte-to-claim bindings, NOT authenticated provenance or authority.

Every material blob is caller-supplied. Even matching hashes are self-consistent
claims, not proof of historical PR body, Git ancestry, CI policy or catalog.
Pure/strict: no provider, files, imports of runtime auth, writes or network.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re

from .post_merge_registry_envelope import (
    EvidenceEnvelopeError, exact, inspect_candidate, need, text,
)

_START = '<!-- fortis-release-impact:start -->\n```yaml\n'
_END = '\n```\n<!-- fortis-release-impact:end -->'
_TARGET = re.compile(r'[a-z][a-z0-9-]{0,99}\Z')


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeEncodeError, OverflowError) as exc:
        raise EvidenceEnvelopeError('MATERIAL_NOT_CANONICAL_JSON') from exc


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _bytes(value, label, bound):
    need(type(value) is str, label + '_NOT_TEXT')
    try:
        raw = value.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise EvidenceEnvelopeError(label + '_UNICODE_INVALID') from exc
    need(0 < len(raw) <= bound, label + '_SIZE_INVALID')
    return raw


def _path(value):
    if not isinstance(value, str) or not value or len(value) > 240:
        return False
    if value.startswith('/') or '\\' in value or '\0' in value or '\r' in value or '\n' in value:
        return False
    parts = value.split('/')
    # Reviewed repositories legitimately contain .github/, .dockerignore etc.
    # Reject .git internals, traversal and noncanonical separators instead.
    if any(part in ('.', '..', '', '.git') for part in parts):
        return False
    return str(PurePosixPath(value)) == value


def _impact_yaml(body):
    # Exactly one reviewed annotation: never infer absent/duplicate impact.
    need(body.count('<!-- fortis-release-impact:start -->') == 1 and
         body.count('<!-- fortis-release-impact:end -->') == 1 and
         body.count(_START) == 1 and body.count(_END) == 1,
         'IMPACT_MARKER_INVALID')
    before, remainder = body.split(_START, 1)
    impact, after = remainder.split(_END, 1)
    need(bool(impact) and len(impact) <= 20_000 and
         '```' not in impact and '<!-- fortis-release-impact:' not in impact and
         '\r' not in impact, 'IMPACT_YAML_INVALID')
    # Exact bytes between delimiters, excluding the one newline before ```.
    return impact


def _paths(rows, expected):
    need(type(rows) is list and len(rows) <= 10_000 and
         len(rows) == expected['count'], 'PATH_COUNT_MISMATCH')
    seen = set()
    order = []
    for item in rows:
        exact(item, ('status', 'path', 'previousPath'), 'PATH_ROW_FIELDS_INVALID')
        status = item['status']
        target = item['path']
        previous = item['previousPath']
        need(status in ('added', 'modified', 'deleted', 'renamed') and
             _path(target), 'PATH_ROW_INVALID')
        need((status == 'renamed' and _path(previous) and previous != target) or
             (status != 'renamed' and previous is None), 'PATH_RENAME_INVALID')
        need(target not in seen, 'PATH_DUPLICATE')
        seen.add(target)
        order.append((target, status, previous or ''))
    need(order == sorted(order), 'PATH_ORDER_INVALID')
    need(_digest(_canonical(rows)) == expected['sha256'], 'PATH_CONTENT_DIGEST_MISMATCH')


def _map_rows(rows):
    need(type(rows) is list and len(rows) <= 200, 'COMPONENT_MAP_INVALID')
    targets = []
    for item in rows:
        exact(item, ('targetId', 'componentIds', 'resourceIds'), 'COMPONENT_MAP_FIELDS_INVALID')
        tid = item['targetId']
        need(type(tid) is str and _TARGET.fullmatch(tid),
             'COMPONENT_TARGET_INVALID')
        for key in ('componentIds', 'resourceIds'):
            names=item[key]
            need(type(names) is list and len(names) <= 100 and
                 all(text(s,100) for s in names) and names == sorted(set(names)),
                 'COMPONENT_MAP_MEMBERS_INVALID')
        targets.append(tid)
    need(targets == sorted(set(targets)), 'COMPONENT_MAP_DUPLICATE_OR_UNSORTED')


def bind_claimed_material(envelope, material):
    """Check *supplied* bytes against *supplied* envelope digests.

    Result is SOURCE_BYTES_MATCH_UNTRUSTED. No status is ever VERIFIED/ALLOWED.
    The next privileged collector must independently fetch and authenticate
    reviewed bytes, Git merge graph, branch rules, CI and pinned catalog.
    """
    summary = inspect_candidate(envelope)
    exact(material, ('catalogText', 'componentMap', 'dependencyEdges', 'pullRequests'),
          'MATERIAL_FIELDS_INVALID')
    need(len(_canonical(material)) <= 2_000_000, 'MATERIAL_TOO_LARGE')
    cat = envelope['catalog']
    catalog_bytes = _bytes(material['catalogText'], 'CATALOG', 250_000)
    need(_digest(catalog_bytes) == cat['contentSha256'], 'CATALOG_BYTES_DIGEST_MISMATCH')
    _map_rows(material['componentMap'])
    need(_digest(_canonical(material['componentMap'])) == cat['componentMapSha256'],
         'COMPONENT_MAP_DIGEST_MISMATCH')
    deps = material['dependencyEdges']
    need(type(deps) is list and deps == envelope['dependencyClosure']['edges'] and
         _digest(_canonical(deps)) == envelope['dependencyClosure']['digest'],
         'DEPENDENCY_CONTENT_MISMATCH')
    prs = material['pullRequests']
    expected = envelope['mergedPullRequests']
    need(type(prs) is list and len(prs) == len(expected), 'MATERIAL_PR_COUNT_INVALID')
    numbers = []
    for claimed, supplied in zip(expected, prs):
        exact(supplied, ('number', 'reviewedBodyText', 'changedPathRecords',
                         'ciRequiredPolicy'), 'PR_MATERIAL_FIELDS_INVALID')
        need(type(supplied['number']) is int and supplied['number'] == claimed['number'],
             'PR_MATERIAL_ORDER_OR_ID_MISMATCH')
        numbers.append(supplied['number'])
        body_bytes = _bytes(supplied['reviewedBodyText'], 'REVIEWED_BODY', 50_000)
        need(_digest(body_bytes) == claimed['reviewedBody']['bodySha256'],
             'REVIEWED_BODY_DIGEST_MISMATCH')
        impact = _impact_yaml(supplied['reviewedBodyText'])
        need(_digest(impact.encode('utf-8')) == claimed['releaseImpactSha256'],
             'IMPACT_YAML_DIGEST_MISMATCH')
        _paths(supplied['changedPathRecords'], claimed['changedPaths'])
        policy = exact(supplied['ciRequiredPolicy'], ('requiredChecks',),
                       'CI_POLICY_FIELDS_INVALID')
        names = policy['requiredChecks']
        need(type(names) is list and names == claimed['ci']['requiredChecks'] and
             _digest(_canonical(policy)) == claimed['ci']['policySha256'],
             'CI_POLICY_CONTENT_MISMATCH')
    need(numbers == sorted(set(numbers)), 'MATERIAL_PR_DUPLICATE_OR_UNSORTED')
    return {
        'result': 'SOURCE_BYTES_MATCH_UNTRUSTED',
        'candidateDigest': summary['candidateDigest'],
        'materialDigest': _digest(_canonical(material)),
        'matchedPrCount': len(prs),
        'matchedPathCount': sum(len(p['changedPathRecords']) for p in prs),
        'evidenceVerified': False,
        'admissionAllowed': False,
        'deploymentAllowed': False,
        'unverified': [
            'PROVIDER_AUTHENTICITY', 'REVIEW_CUTOFF_PROVENANCE',
            'MERGE_ANCESTRY', 'CI_PROVIDER_ATTESTATION',
            'CATALOG_GIT_BLOB_AND_COMPONENT_BINDINGS',
            'DEPENDENCY_SOURCE_COMPLETENESS',
        ],
    }
