"""Pure projection of an independently validated catalog and resolved binding.

The existing source/validator composition must authenticate and pin the
raw catalog bytes and resolved mapping; this function is not that verifier.
No runtime grant, no alternate maintained graph, no provider readiness.
External repository refs remain unresolved rather than guessing ownership.
"""
import re

from ...core import canonical
from . import semantic_contract as sc


_NAME=re.compile(r'[a-z0-9][a-z0-9._/-]{0,127}\Z')


def _name(value):
    return type(value) is str and _NAME.fullmatch(value) is not None and '//' not in value and '..' not in value


def _names(values,*,empty=True):
    return (type(values) is list and (empty or bool(values)) and len(values)<=256
            and all(_name(v) for v in values) and values==sorted(set(values)))


def resolve_components(ref,catalog):
    """Validate all enrolled targets, not just those affected by one PR."""
    targets={t['id']:t for t in catalog['targets']}
    sc.need(0<len(targets)==len(catalog['targets'])<=200,'P5_COMPONENT_TARGET_SET')
    components=ref['components'];bindings=ref['bindings']
    sc.need(type(components) is list and 0<len(components)<=256
          and type(bindings) is list and len(bindings)==len(targets),'P5_COMPONENT_BINDING_SET')
    graph={}
    for row in components:
        sc.need(type(row) is dict and set(row)=={'id','resources','requires'} and _name(row['id'])
              and row['id'] not in graph and _names(row['resources'],empty=False)
              and _names(row['requires']),'P5_COMPONENT_GRAPH_INVALID')
        graph[row['id']]=row
    sc.need(list(graph)==sorted(graph),'P5_COMPONENT_GRAPH_ORDER')
    visited=set();active=set()
    def visit(ident):
        sc.need(ident in graph and ident not in active,'P5_COMPONENT_GRAPH_CYCLE_OR_UNKNOWN')
        if ident in visited:return
        active.add(ident)
        for dep in graph[ident]['requires']:visit(dep)
        active.remove(ident);visited.add(ident)
    for ident in graph:visit(ident)
    by_target={};used=set()
    for row in bindings:
        sc.need(type(row) is dict and set(row)=={'targetId','environment','componentId'}
              and _name(row['targetId']) and row['targetId'] in targets and row['targetId'] not in by_target
              and _name(row['componentId']) and row['componentId'] in graph
              and row['componentId'] not in used,'P5_COMPONENT_TARGET_BINDING_INVALID')
        target=targets[row['targetId']]
        sc.need(type(row['environment']) is str and row['environment'] in target['deployment']['environments'],
              'P5_COMPONENT_ENVIRONMENT_MISMATCH')
        by_target[row['targetId']]=row;used.add(row['componentId'])
    sc.need(list(by_target)==sorted(targets) and used==set(graph),'P5_COMPONENT_BINDING_SET')
    result=[]
    for tid,row in by_target.items():
        target=targets[tid];component=graph[row['componentId']]
        required=set()
        for dep in target.get('dependsOn',[]):
            sc.need(dep['repository']=='fortis-approvals' and dep['target'] in by_target,
                  'P5_COMPONENT_EXTERNAL_OR_UNKNOWN_DEPENDENCY')
            required.add(by_target[dep['target']]['componentId'])
        sc.need(required<=set(component['requires']),'P5_COMPONENT_DEPENDENCY_MAPPING_INCOMPLETE')
        result.append({**row,'resourceIds':component['resources'],
                       'requiresComponentIds':component['requires'],
                       'deployment':target['deployment'],'buildUnit':target.get('buildUnit'),
                       'verification':target['verification']})
    return result


def from_resolved_catalog(catalog, resolved, *, repository, catalog_sha256, build_pins):
    sc.repository(repository)
    sc.hex_id(catalog_sha256,64)
    sc.need(type(catalog) is dict and type(catalog.get('schemaVersion')) is int
            and catalog['schemaVersion'] in (1,2)
            and catalog['repository']==repository.split('/')[1])
    sc.need(type(resolved) is list and 0<len(resolved)<=200 and type(build_pins) is dict)
    targets={t['id']:t for t in catalog['targets']}
    units={b['id']:b for b in catalog['buildUnits']}
    rows={r['targetId']:r for r in resolved}
    by_component={r['componentId']:r for r in resolved}
    sc.need(len(targets)==len(catalog['targets'])==len(rows)==len(resolved)==len(by_component)
            and set(targets)==set(rows) and set(build_pins)<=set(units))
    def subject(row):
        return {'repository':repository,'targetId':row['targetId'],'environment':row['environment']}
    result=[]
    for tid,row in sorted(rows.items()):
        t=targets[tid]
        sc.need(row['deployment']==t['deployment'] and row['environment'] in t['deployment']['environments']
                and row['buildUnit']==t.get('buildUnit') and row['verification']==t['verification'])
        required=set(row['requiresComponentIds'])
        sc.need(required<=set(by_component))
        deps={canonical(subject(by_component[c])):subject(by_component[c]) for c in required}
        unresolved=[]
        for dep in t.get('dependsOn',[]):
            if dep['repository']==catalog['repository'] and dep['target'] in rows:
                other=rows[dep['target']]
                sc.need(other['componentId'] in required, 'REGISTRY_PROFILE_DEPENDENCY_BINDING')
                deps[canonical(subject(other))]=subject(other)
            else:
                unresolved.append(dep)
        build=None
        if row['buildUnit'] is not None:
            ident=row['buildUnit']
            sc.need(ident in units)
            pins=build_pins.get(ident)
            if pins is not None:
                sc.fields(pins,('recipeDigest','configDigest'))
                for v in pins.values():sc.hex_id(v,64)
            else:
                pins={'recipeDigest':None,'configDigest':None}
            build={'buildUnitId':ident,**pins}
        maintenance=t['maintenance'] if catalog['schemaVersion']==2 else None
        result.append({'subject':subject(row),'componentId':row['componentId'],
             'resources':sorted(row['resourceIds']),'dependencies':[deps[k] for k in sorted(deps)],
             'unresolvedDependencies':sorted(unresolved,key=canonical),
             'maintenance':maintenance,'procedure':row['deployment']['procedure'],
             'verification':sorted(row['verification']),'build':build,
             'deployable':row['deployment']['kind']!='none'})
    return {'schemaVersion':1,'repository':repository,'catalogSha256':catalog_sha256,'subjects':result}
