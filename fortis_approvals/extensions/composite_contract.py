"""Image-owned V1 composite definition metadata and pure group expansion.

Not registered with Core/Provider yet. No runtime policy, credential,
approval, grant, dispatch, continuation or external effect is created here.
"""
from dataclasses import dataclass
import uuid

from ..integrations.registry_contracts.semantic_contract import (
    digest, need, uuid_id, validate_params,
)


@dataclass(frozen=True)
class Definition:
    service: str
    operation: str
    version: int
    children: tuple
    expansion: str
    protected_owner_gate: bool = False

    def metadata(self):
        return {
            'service': self.service, 'operation': self.operation,
            'version': self.version, 'operationKind': 'composite',
            'children': [{'service': service, 'operation': operation, 'version': version}
                         for service, operation, version in self.children],
            'expansion': self.expansion,
            'protectedOwnerGate': self.protected_owner_gate,
        }

    @property
    def definition_digest(self):
        return digest(self.metadata())


# Only trusted source defines children. Initial policies belong to the
# existing owner policy store; the protected merge gate is not autonomy.
_DEFINITIONS = (
    Definition('registry', 'begin_release_group', 1,
               (('registry', 'begin_release', 1),), 'ordered_subjects'),
    Definition('registry', 'report_release_results', 1,
               (('registry', 'report_release_result', 1),), 'ordered_subjects'),
    Definition('release', 'merge_and_register', 1,
               (('github', 'merge_pull_request', 1),
                ('registry', 'register_merge', 1)), 'bound_verified_outputs', True),
)


def definitions():
    return _DEFINITIONS


def definition(service, operation):
    match = next((row for row in _DEFINITIONS
                  if row.service == service and row.operation == operation), None)
    need(match is not None, 'COMPOSITE_DEFINITION_UNKNOWN')
    return match


def expand_group(service, operation, parent_id, params):
    """Deterministic planned step intents, never callable child permissions.

    Merge output bindings need a separate reviewed implementation. No
    fallback expansion for unsupported recipes or caller-supplied workflows.
    """
    uuid_id(parent_id)
    recipe = definition(service, operation)
    need(recipe.expansion == 'ordered_subjects', 'COMPOSITE_EXPANSION_UNSUPPORTED')
    parsed = validate_params(operation, params)
    child_service, child_operation, child_version = recipe.children[0]
    params_digest = digest(parsed)
    steps = []
    for ordinal, item in enumerate(parsed['items']):
        payload_digest = digest(item)
        binding = {
            'parentId': parent_id, 'definitionDigest': recipe.definition_digest,
            'ordinal': ordinal, 'paramsDigest': params_digest,
            'service': child_service,
            'operation': child_operation, 'version': child_version,
            'payloadDigest': payload_digest,
        }
        step_id = str(uuid.uuid5(uuid.UUID(parent_id), digest(binding)))
        steps.append({**binding, 'stepId': step_id, 'params': item})
    return {
        'parentId': parent_id, 'definitionDigest': recipe.definition_digest,
        'paramsDigest': params_digest, 'steps': steps,
    }


def expand_composite(service, operation, parent_id, params):
    if (service,operation)!=('release','merge_and_register'):
        return expand_group(service,operation,parent_id,params)
    from ..integrations.registry_contracts.source_lineage_contract import merge_expansion
    result=merge_expansion(parent_id,params)
    need(result['definitionDigest']==definition(service,operation).definition_digest,
         'COMPOSITE_DEFINITION_CHANGED')
    return result
