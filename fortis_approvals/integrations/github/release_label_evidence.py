"""Bounded Release Label evidence; no new authority, journal or write path."""
import re

from ...core import Denied
from .contract import validate_github_action
from .release_label_contract import MAX_LABELS, checked_names, names_hash
from ...workflow.common import require

LABEL_OPERATIONS = frozenset({'add_pr_release_labels', 'remove_pr_release_label'})


def release_label_receipt_matches(operation, repository, params, request_id, receipt):
    """Bind the entire label delta to the original precondition fingerprint.

    At most five adds give 32 possible prior sets, including already-present
    labels. One removal gives two. No prior snapshot or parallel journal is
    needed; unrelated labels must survive exactly, and changed must agree.
    """
    try:
        if operation not in LABEL_OPERATIONS or type(receipt) is not dict:
            return False
        validate_github_action(operation, repository, params)
        if (receipt.get('requestId') != request_id or
                receipt.get('operation') != operation or
                receipt.get('repository') != repository or
                type(receipt.get('number')) is not int or
                receipt['number'] != params['number'] or
                receipt.get('headSha') != params['expectedHeadSha'] or
                type(receipt.get('changed')) is not bool):
            return False
        after = set(checked_names(receipt.get('labels')))
        if operation == 'add_pr_release_labels':
            selected = params['labels']
            if not set(selected).issubset(after):
                return False
            fixed = after - set(selected)
            candidates = (fixed | {name for index, name in enumerate(selected)
                                   if mask & (1 << index)}
                          for mask in range(1 << len(selected)))
        else:
            if params['name'] in after:
                return False
            candidates = (after, after | {params['name']})
        for before in candidates:
            if (len(before) <= MAX_LABELS and
                    names_hash(sorted(before)) == params['expectedLabelsSha256'] and
                    receipt['changed'] == (before != after)):
                return True
        return False
    except (Denied, KeyError, TypeError, ValueError):
        return False


def _context(value, number):
    require(type(value) is dict and
            value.get('operation') == 'get_pr_release_label_context' and
            type(value.get('number')) is int and value['number'] == number,
            'INCIDENT_LABEL_CONTEXT_INVALID')
    for key, width in (('headSha', 40), ('baseSha', 40),
                       ('bodySha256', 64), ('labelsSha256', 64)):
        require(type(value.get(key)) is str and
                re.fullmatch('[0-9a-f]{' + str(width) + '}', value[key]) is not None,
                'INCIDENT_LABEL_CONTEXT_INVALID')
    names = checked_names(value.get('labels'))
    require(names_hash(names) == value['labelsSha256'] and
            type(value.get('branch')) is str and
            value['branch'].startswith('task/') and len(value['branch']) <= 120,
            'INCIDENT_LABEL_CONTEXT_INVALID')
    return {key: value[key] for key in ('number', 'headSha', 'baseSha',
            'bodySha256', 'labelsSha256', 'branch')} | {'labels': names}


def read_release_label_evidence(github, repository, operation, params, receipt):
    """Two fresh, bounded typed READs; provider state never attributes an effect."""
    validate_github_action(operation, repository, params)
    first = _context(github.get_pr_release_label_context(
        repository, params['number']), params['number'])
    final = _context(github.get_pr_release_label_context(
        repository, params['number']), params['number'])
    require(first == final, 'INCIDENT_LABEL_CONTEXT_CHANGED')
    matching = all(first[key] == params['expected' + key[0].upper() + key[1:]]
                   for key in ('headSha', 'baseSha', 'bodySha256'))
    names = first['labels']
    delta = (all(name in names for name in params['labels'])
             if operation == 'add_pr_release_labels' else params['name'] not in names)
    return dict(status='OBSERVED', scope='EXACT_RELEASE_LABEL_CONTEXT',
                pullNumber=params['number'], headShaMatches=first['headSha'] == params['expectedHeadSha'],
                requestFingerprintsMatch=matching, labelInventoryComplete=True,
                labelsSha256=first['labelsSha256'], labelCount=len(names),
                desiredStateObserved=matching and delta,
                originalLabelsObserved=first['labelsSha256'] == params['expectedLabelsSha256'],
                receiptLabelsMatch=(type(receipt) is dict and
                    names_hash(receipt['labels']) == first['labelsSha256']),
                effectAttribution='UNKNOWN')
