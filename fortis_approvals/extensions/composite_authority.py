"""Exact contextual admission against existing UnifiedPolicyCore decisions.

Source-owned enrollment data must be part of a separately reviewed policy
authority. No public configuration, method grant, policy edit or runtime
activation is performed here. The actual provider still owns readiness,
credential, maintenance and effect-time guards.
"""
from dataclasses import dataclass
from types import MappingProxyType

from ..core import canonical, loads_strict
from ..integrations.registry_contracts.semantic_contract import (
    digest, fields, hex_id, need, subject, subject_key, validate_params,
)
from .composite_contract import definition
from .composite_executor import Admission
from .owner_policy_engine_v2 import PolicyAdmission, UnifiedPolicyCore, _coordinate

_GROUP_CHILD = MappingProxyType({
    'begin_release_group': 'begin_release',
    'report_release_results': 'report_release_result',
})


@dataclass(frozen=True)
class ContextGrant:
    actor: str
    parent_operation: str
    parent_target: str
    child_target: str
    repository: str
    target_id: str
    environment: str
    definition_digest: str

    def record(self):
        parent = _coordinate((self.actor, 'registry', self.parent_operation, self.parent_target))
        need(self.parent_operation in _GROUP_CHILD, 'COMPOSITE_CONTEXT_RECIPE_DENIED')
        child = _coordinate((self.actor, 'registry',
                             _GROUP_CHILD[self.parent_operation], self.child_target))
        item = {'repository': self.repository, 'targetId': self.target_id,
                'environment': self.environment}
        subject(item)
        need(self.definition_digest == definition('registry', self.parent_operation).definition_digest,
             'COMPOSITE_CONTEXT_DEFINITION_CHANGED')
        return {'parent': list(parent), 'child': list(child), 'subject': item,
                'definitionDigest': self.definition_digest}


@dataclass(frozen=True)
class MergeContextGrant:
    actor: str
    parent_target: str
    child_service: str
    child_operation: str
    child_target: str
    repository: str
    definition_digest: str

    def record(self):
        from ..integrations.registry_contracts.semantic_contract import repository
        recipe=definition('release','merge_and_register')
        repository(self.repository)
        need((self.child_service,self.child_operation,1) in recipe.children and
             self.definition_digest==recipe.definition_digest,'MERGE_CONTEXT_RECIPE_DENIED')
        parent=_coordinate((self.actor,'release','merge_and_register',self.parent_target))
        child=_coordinate((self.actor,self.child_service,self.child_operation,self.child_target))
        return {'parent':list(parent),'child':list(child),'repository':self.repository,
                'definitionDigest':self.definition_digest}


def _grant_key(row):
    if 'subject' in row:
        return (tuple(row['parent']),subject_key(row['subject']))
    return (tuple(row['parent']),(row['repository'],row['child'][1],row['child'][2]))


class ContextEnrollment:
    """Immutable, exact finite relation; never an actor wildcard or policy."""

    def __init__(self, grants, *, source_digest, expected_digest):
        hex_id(source_digest, 64)
        hex_id(expected_digest, 64)
        need(type(grants) is tuple and 0 < len(grants) <= 1000
             and all(type(g) in (ContextGrant, MergeContextGrant) for g in grants), 'COMPOSITE_CONTEXT_GRANTS_INVALID')
        rows = [g.record() for g in grants]
        keys = [_grant_key(r) for r in rows]
        need(len(keys) == len(set(keys)), 'COMPOSITE_CONTEXT_DUPLICATE')
        value = {'schemaVersion': 1, 'sourceDigest': source_digest,
                 'grants': sorted(rows, key=canonical)}
        need(digest(value) == expected_digest, 'COMPOSITE_CONTEXT_PIN_MISMATCH')
        self._value = canonical(value)
        self._digest = expected_digest
        self._rows = MappingProxyType({key: canonical(row) for key, row in zip(keys, rows)})

    @classmethod
    def from_reviewed_rows(cls, rows, *, source_digest, expected_digest):
        need(type(rows) is list and 0 < len(rows) <= 1000, 'COMPOSITE_CONTEXT_GRANTS_INVALID')
        grants = []
        for row in rows:
            fields(row, ('parent', 'child', 'definitionDigest',
                         'subject' if type(row) is dict and 'subject' in row else 'repository'))
            parent, child = row['parent'], row['child']
            need(type(parent) is list and len(parent) == 4
                 and type(child) is list and len(child) == 4,
                 'COMPOSITE_CONTEXT_GRANTS_INVALID')
            if 'subject' in row:
                item = row['subject']
                subject(item)
                grant = ContextGrant(parent[0], parent[2], parent[3], child[3],
                                     item['repository'], item['targetId'], item['environment'],
                                     row['definitionDigest'])
            else:
                grant = MergeContextGrant(parent[0], parent[3], child[1], child[2], child[3],
                                          row['repository'], row['definitionDigest'])
            need(grant.record() == row, 'COMPOSITE_CONTEXT_GRANTS_INVALID')
            grants.append(grant)
        return cls(tuple(grants), source_digest=source_digest, expected_digest=expected_digest)

    @property
    def sha(self):
        return self._digest

    def metadata(self):
        return loads_strict(self._value)

    def match(self, actor, parent_target, step):
        # The trusted expansion defines the child, not a caller-controlled op.
        fields(step, ('parentId', 'definitionDigest', 'ordinal', 'paramsDigest',
                      'service', 'operation', 'version', 'payloadDigest', 'stepId', 'params'))
        if (step.get('service'),step.get('operation')) in (
                ('github','merge_pull_request'),('registry','register_merge')):
            from .composite_contract import expand_composite
            from ..integrations.registry_contracts.source_lineage_contract import proposal
            p=proposal(step['params']['proposal'])
            expansion=expand_composite('release','merge_and_register',step['parentId'],p)
            ordinal=step['ordinal']
            need(type(ordinal) is int and 0<=ordinal<2 and expansion['steps'][ordinal]==step,
                 'MERGE_CONTEXT_PAYLOAD_CHANGED')
            coord=_coordinate((actor,'release','merge_and_register',parent_target))
            raw=self._rows.get((coord,(p['repository'],step['service'],step['operation'])))
            need(raw is not None,'MERGE_CONTEXT_SCOPE_DENIED')
            row=loads_strict(raw)
            need(row['repository']==p['repository'] and row['definitionDigest']==step['definitionDigest'],
                 'MERGE_CONTEXT_SCOPE_DENIED')
            return row
        need(step.get('service') == 'registry'
             and type(step.get('operation')) is str
             and type(step.get('version')) is int and step['version'] == 1,
             'COMPOSITE_CONTEXT_STEP_DENIED')
        op = next((p for p, c in _GROUP_CHILD.items() if c == step['operation']), None)
        need(op is not None, 'COMPOSITE_CONTEXT_RECIPE_DENIED')
        params = validate_params(step['operation'], step['params'])
        need(digest(params) == step['payloadDigest'], 'COMPOSITE_CONTEXT_PAYLOAD_CHANGED')
        coord = _coordinate((actor, 'registry', op, parent_target))
        raw = self._rows.get((coord, subject_key(params['subject'])))
        need(raw is not None, 'COMPOSITE_CONTEXT_SCOPE_DENIED')
        row = loads_strict(raw)
        # Exact enrolled subject spelling is retained (no aliases).
        need(row['subject'] == params['subject']
             and row['definitionDigest'] == step['definitionDigest'],
             'COMPOSITE_CONTEXT_SCOPE_DENIED')
        return row


@dataclass(frozen=True)
class ProviderGuard:
    ready: bool
    granted: bool
    hard_floor: str
    generation_digest: str


def _explicit_decision(core, coord, overlay, legacy):
    # No actor/default/global fallback to an unenrolled target. V1 context
    # accepts only exact literal coordinates. Conditional providers need a
    # separately reviewed effect-time contract, not relaxed inheritance.
    need(core.auth.active(coord[0]) and coord in core.authority.choices
         and coord in core.authority.baseline
         and type(core.authority.baseline[coord]) is str,
         'COMPOSITE_CONTEXT_COORDINATE_DENIED')
    core.authority.admitted(coord)
    return core.authority.decision(coord, overlay, legacy)


class ContextAdmission:
    """Pure scoped decision from actual owner policy snapshot + provider guard.

    guard is trusted source, must independently check the registered child
    grant, readiness, exact subject, inner hard floor and credential
    generation. An admitted context cannot create any of these.
    """

    def __init__(self, core, enrollment, *, guard):
        need(isinstance(core, UnifiedPolicyCore) and type(enrollment) is ContextEnrollment
             and callable(guard), 'COMPOSITE_CONTEXT_BINDING_REQUIRED')
        self.core, self.enrollment, self.guard = core, enrollment, guard

    def admit(self, actor, parent_target, step):
        authority = self.core.authority
        need(authority is not None and type(authority.scope_binding) is dict
             and authority.scope_binding.get('compositeContext') == self.enrollment.sha,
             'COMPOSITE_CONTEXT_NOT_ENROLLED')
        # The scope object itself is trusted source, but must still match
        # the authority digest that was installed (not a later dict edit).
        need(PolicyAdmission(self.core, dict(authority.choices),
                             scope_binding=authority.scope_binding).sha == authority.sha,
             'COMPOSITE_CONTEXT_AUTHORITY_DRIFT')
        row = self.enrollment.match(actor, parent_target, step)
        with self.core._db() as db:
            db.execute('BEGIN')
            rev, overlay, legacy = self.core._snapshot(db)
            parent = _explicit_decision(self.core, tuple(row['parent']), overlay, legacy)
            child = _explicit_decision(self.core, tuple(row['child']), overlay, legacy)
            need(parent in ('ALLOW', 'ASK') and child in ('ALLOW', 'ASK'),
                 'COMPOSITE_CONTEXT_POLICY_DENIED')
            guard = self.guard(actor, loads_strict(canonical(row)), loads_strict(canonical(step)))
            need(type(guard) is ProviderGuard and guard.ready is True and guard.granted is True
                 and guard.hard_floor == ('ASK' if row['child'][1:3]==['github','merge_pull_request'] else 'ALLOW'),
                 'COMPOSITE_CONTEXT_PROVIDER_DENIED')
            hex_id(guard.generation_digest, 64)
            # Revision and source binding included; no credentials persisted.
            generation = digest({'authority': authority.sha, 'revision': rev,
                                 'enrollment': self.enrollment.sha,
                                 'grant': row, 'providerGeneration': guard.generation_digest,
                                 'parentPolicy': parent, 'childPolicy': child})
            return Admission(child, True, guard.hard_floor, generation)


def reviewed_additive_authority(core, *, predecessor, enrollment, choices,
                               scope_binding, expected_predecessor_digest,
                               expected_successor_digest, semantic_enrollment=None):
    """Validate a proposed additive epoch; does NOT install it.

    Real predecessor reconstruction, historical epoch replay and owner
    release approval remain mandatory. No database rows select a baseline.
    This only admits exact new group/child coordinates and preserves every
    old baseline/choice unchanged. New coordinates start DENY; owner editor
    changes them after actual independent grants are admitted.
    """
    need(isinstance(core, UnifiedPolicyCore) and type(predecessor) is PolicyAdmission
         and type(enrollment) is ContextEnrollment and type(choices) is dict
         and type(scope_binding) is dict, 'COMPOSITE_SUCCESSOR_BINDING_REQUIRED')
    hex_id(expected_predecessor_digest, 64)
    hex_id(expected_successor_digest, 64)
    need(predecessor.sha == expected_predecessor_digest
         and scope_binding.get('compositeContext') == enrollment.sha,
         'COMPOSITE_SUCCESSOR_PIN_MISMATCH')
    old_scope = predecessor.scope_binding
    added_scope={'compositeContext'}
    semantic_coords=set()
    if semantic_enrollment is not None:
        from .semantic_enrollment import SemanticEnrollment
        need(type(semantic_enrollment) is SemanticEnrollment and
             scope_binding.get('semanticScope')==semantic_enrollment.sha,
             'SEMANTIC_SCOPE_PIN_CHANGED')
        semantic_coords=semantic_enrollment.coordinates()
        added_scope.add('semanticScope')
    need(type(old_scope) is dict and not (set(old_scope)&added_scope)
         and {k: v for k, v in scope_binding.items() if k not in added_scope} == old_scope,
         'COMPOSITE_SUCCESSOR_SCOPE_CHANGED')
    old = dict(predecessor.baseline)
    old_choices = dict(predecessor.choices)
    need(not any(k in old and k[1:3]!=('github','list_pull_requests') for k in semantic_coords),
         'SEMANTIC_LEGACY_COORDINATE_REUSE_DENIED')

    need(all(k in core.policies and core.policies[k] == v for k, v in old.items())
         and all(k in choices and frozenset(choices[k]) == v for k, v in old_choices.items()),
         'COMPOSITE_SUCCESSOR_PREDECESSOR_CHANGED')
    enrolled = {tuple(row[key]) for row in enrollment.metadata()['grants']
                for key in ('parent', 'child')}
    enrolled |= semantic_coords
    added = set(core.policies) - set(old)
    need(added == set(choices) - set(old_choices)
         and added <= enrolled and enrolled <= set(choices)
         and all(core.policies[k] == 'DENY'
                 and frozenset(choices[k]) == frozenset(('DENY', 'ASK', 'ALLOW'))
                 for k in added),
         'COMPOSITE_SUCCESSOR_ADDITION_DENIED')
    successor = PolicyAdmission(core, choices, scope_binding=scope_binding)
    need(successor.sha == expected_successor_digest, 'COMPOSITE_SUCCESSOR_PIN_MISMATCH')
    return successor
