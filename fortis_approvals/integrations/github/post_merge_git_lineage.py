"""P5 offline Git SHA-1 commit-object linkage, NOT provider authentication.

Checks hash-bound first-parent paths for claimed GitHub 'merge commit' PRs.
Raw commit bytes are supplied by the caller; no Git/network/filesystem/keys.
Even a consistent DAG does NOT prove this was a provider's accepted main.
"""
from __future__ import annotations

import hashlib
import json
import re

from .post_merge_registry_envelope import EvidenceEnvelopeError, inspect_candidate, need, sha

_HEX = re.compile(r'[0-9a-f]*\Z')
_SHA_BYTES = re.compile(rb'[0-9a-f]{40}\Z')
_MAX_OBJECTS = 1024
_MAX_RAW_OBJECT = 64_000
_MAX_TOTAL_BYTES = 4_000_000


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _read_commit(item):
    need(type(item) is dict and set(item) == {'sha', 'rawHex'},
         'COMMIT_OBJECT_FIELDS_INVALID')
    claimed = item['sha']
    hexed = item['rawHex']
    need(sha(claimed), 'COMMIT_OBJECT_SHA_INVALID')
    need(type(hexed) is str and len(hexed) <= _MAX_RAW_OBJECT * 2 and
         len(hexed) % 2 == 0 and _HEX.fullmatch(hexed) is not None,
         'COMMIT_OBJECT_HEX_INVALID')
    raw = bytes.fromhex(hexed)
    need(bool(raw) and b'\0' not in raw, 'COMMIT_OBJECT_RAW_INVALID')
    signed = b'commit ' + str(len(raw)).encode('ascii') + b'\0' + raw
    need(hashlib.sha1(signed).hexdigest() == claimed, 'COMMIT_OBJECT_SHA_MISMATCH')
    header, sep, _message = raw.partition(b'\n\n')
    need(bool(sep), 'COMMIT_OBJECT_HEADER_MISSING')
    lines = header.split(b'\n')
    need(bool(lines) and lines[0].startswith(b'tree ') and
         _SHA_BYTES.fullmatch(lines[0][5:]) is not None,
         'COMMIT_TREE_INVALID')
    parents = []
    stage = 0
    has_author = False
    has_committer = False
    for line in lines[1:]:
        need(line and b'\r' not in line, 'COMMIT_HEADER_INVALID')
        if line.startswith(b'parent '):
            need(stage == 0 and _SHA_BYTES.fullmatch(line[7:]) is not None and
                 len(parents) < 8 and line[7:].decode() not in parents,
                 'COMMIT_PARENTS_INVALID')
            parents.append(line[7:].decode('ascii'))
        elif line.startswith(b'author '):
            need(not has_author and not has_committer and len(line) > 7,
                 'COMMIT_AUTHOR_INVALID')
            has_author = True
            stage = 1
        elif line.startswith(b'committer '):
            need(has_author and not has_committer and len(line) > 10,
                 'COMMIT_COMMITTER_INVALID')
            has_committer = True
            stage = 2
        elif line.startswith(b' '):
            need(stage == 3, 'COMMIT_CONTINUATION_INVALID')
        else:
            need(has_committer and b' ' in line and not line.startswith(b'tree '),
                 'COMMIT_HEADER_INVALID')
            stage = 3
    need(has_author and has_committer, 'COMMIT_IDENTITY_FIELDS_MISSING')
    return {'sha': claimed, 'parents': parents, 'treeSha': lines[0][5:].decode('ascii')}


def check_claimed_first_parent(envelope, commit_objects):
    """Validate supplied SHA-1 Git merge graph against an untrusted envelope.

    Only accepts ordinary two-parent merge commits, with PR head as second
    parent. Other merge strategies must STOP for separate contract review.
    """
    source = inspect_candidate(envelope)
    need(type(commit_objects) is list and 0 < len(commit_objects) <= _MAX_OBJECTS,
         'COMMIT_PROOF_OBJECT_COUNT_INVALID')
    need(sum(len(row.get('rawHex', '')) if type(row) is dict and
             type(row.get('rawHex')) is str else 0 for row in commit_objects)
         <= 2 * _MAX_TOTAL_BYTES, 'COMMIT_PROOF_TOO_LARGE')
    objects = {}
    for row in commit_objects:
        parsed = _read_commit(row)
        need(parsed['sha'] not in objects, 'COMMIT_OBJECT_DUPLICATE')
        objects[parsed['sha']] = parsed
    prs = envelope['mergedPullRequests']
    merges = {pr['mergeSha'] for pr in prs}
    need(len(merges) == len(prs), 'PR_MERGE_SHA_DUPLICATE')
    for pr in prs:
        merge = objects.get(pr['mergeSha'])
        need(merge is not None, 'PR_MERGE_OBJECT_MISSING')
        need(pr['headSha'] in objects, 'PR_HEAD_OBJECT_MISSING')
        need(len(merge['parents']) == 2 and
             merge['parents'][1] == pr['headSha'] and
             merge['parents'][0] != pr['headSha'],
             'PR_MERGE_METHOD_OR_HEAD_MISMATCH')
    cursor = envelope['selectedMainSha']
    found = []
    first_parent_path = []
    visited = set()
    while len(found) < len(merges):
        need(cursor not in visited, 'FIRST_PARENT_CYCLE')
        visited.add(cursor)
        node = objects.get(cursor)
        need(node is not None, 'FIRST_PARENT_PROOF_GAP')
        first_parent_path.append(cursor)
        if cursor in merges:
            found.append(cursor)
        if len(found) == len(merges):
            break
        need(node['parents'], 'FIRST_PARENT_LINEAGE_MISSING')
        cursor = node['parents'][0]
        need(len(first_parent_path) <= _MAX_OBJECTS, 'FIRST_PARENT_TOO_LONG')
    # Reject padding with unrelated objects to keep proof boundaries exact.
    used = set(first_parent_path) | {p['headSha'] for p in prs}
    need(set(objects) == used, 'UNUSED_COMMIT_PROOF_OBJECT')
    normalized = _canonical(sorted(commit_objects, key=lambda row:row['sha']))
    return {
        'result': 'SOURCE_GIT_DAG_MATCH_UNTRUSTED',
        'candidateDigest': source['candidateDigest'],
        'objectProofDigest': hashlib.sha256(normalized).hexdigest(),
        'selectedMainSha': source['selectedMainSha'],
        # Depth is the number of traversed links, not the number of visited nodes.
        'firstParentDepth': len(first_parent_path) - 1,
        'observedMergeShasNewestFirst': found,
        'evidenceVerified': False,
        'admissionAllowed': False,
        'deploymentAllowed': False,
        'missingTrustedProofs': [
            'AUTHENTICATED_PROVIDER_REF_AND_COMPLETE_OBJECT_READ',
            'HISTORICAL_REVIEW_BODY_CUTOFF',
            'CATALOG_TREE_AND_BLOB_PROVENANCE',
            'REQUIRED_CI_POLICY_AND_PROVIDER_ATTEMPTS',
            'COLLECTOR_IDENTITY_AND_PROTECTED_AUDIT',
        ],
    }
