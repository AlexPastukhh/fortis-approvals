"""Scoped, bounded Sonar analysis projections; no historical-snapshot claims."""
from html import unescape
import re

from ....core import Denied
from ...review_schema import (require, text, ident, number, boolean, nullable, array,
                              object_schema, project, context)
from ..analysis_contract import READ_NAMES, GET_ROUTES

T = lambda v: text(v, 4000)
SHORT = lambda v: text(v, 200)
N = nullable
ROW = object_schema
RANGE = ROW({'startLine': number, 'endLine': number,
             'startOffset': lambda x: number(x, minimum=0),
             'endOffset': lambda x: number(x, minimum=0)})
LOCATION = ROW({'component': T, 'msg': N(T), 'textRange': N(RANGE)})
IMPACT = ROW({'softwareQuality': SHORT, 'severity': SHORT})
COMMENT = ROW({'key': ident, 'text': T, 'createdAt': SHORT})
ISSUE = ROW({'key': ident, 'project': ident, 'component': T, 'rule': ident,
             'message': T, 'status': SHORT, 'severity': N(SHORT), 'type': N(SHORT),
             'line': N(number), 'textRange': N(RANGE), 'flows': array(array(LOCATION, 50), 20),
             'impacts': array(IMPACT, 10), 'effort': N(SHORT), 'tags': array(SHORT, 30),
             'assignee': N(SHORT), 'updateDate': SHORT, 'creationDate': N(SHORT),
             'comments': array(COMMENT, 100), 'transitions': array(SHORT, 32)})
MEASURE = ROW({'metric': SHORT, 'value': N(SHORT), 'newValue': N(SHORT),
               'bestValue': N(boolean), 'dataState': SHORT})
COMPONENT = ROW({'key': T, 'path': N(T), 'name': T, 'measures': array(MEASURE, 32)})
CONDITION = ROW({'status': SHORT, 'metricKey': SHORT, 'comparator': N(SHORT),
                 'actualValue': N(SHORT), 'errorThreshold': N(SHORT), 'dataState': SHORT})
ANALYSIS = ROW({'key': ident, 'date': SHORT, 'revision': N(SHORT), 'buildString': N(SHORT)})
BRANCH = ROW({'name': SHORT, 'isMain': boolean, 'type': N(SHORT), 'analysisDate': N(SHORT)})
PR = ROW({'key': ident, 'branch': SHORT, 'base': SHORT, 'analysisDate': N(SHORT)})
SCHEMAS = {
 'list_project_branches': ROW({'items': array(BRANCH, 1000)}),
 'list_project_pull_requests': ROW({'items': array(PR, 1000)}),
 'list_analyses': ROW({'items': array(ANALYSIS), 'total': lambda v: number(v, minimum=0),
                       'page': number, 'pageSize': number, 'complete': boolean}),
 'get_analysis_task': ROW({'id': ident, 'componentKey': ident, 'analysisId': N(ident),
   'status': SHORT, 'submittedAt': N(SHORT), 'startedAt': N(SHORT), 'executedAt': N(SHORT),
   'errorMessage': N(T), 'warnings': array(T, 50)}),
 'get_quality_gate_details': ROW({'analysisId': N(ident), 'status': SHORT,
   'conditions': array(CONDITION), 'ignoredConditions': N(boolean),
   'binding': SHORT, 'snapshot': SHORT}),
 'search_issues': ROW({'issues': array(ISSUE), 'total': lambda v: number(v, minimum=0),
   'page': number, 'pageSize': number, 'hasMore': boolean, 'nextPage': N(number), 'snapshot': SHORT}),
 'get_issue_details': ROW({'issue': ISSUE, 'snapshot': SHORT}),
 'get_issue_history': ROW({'issueKey': ident, 'changes': array(ROW({
   'creationDate': SHORT, 'diffs': array(ROW({'key': SHORT, 'oldValue': N(T), 'newValue': N(T)}), 30)}), 200),
   'snapshot': SHORT}),
 'get_rule': ROW({'key': ident, 'name': T, 'description': lambda v: text(v, 24000),
   'language': N(SHORT), 'severity': N(SHORT), 'type': N(SHORT), 'status': N(SHORT),
   'tags': array(SHORT, 50)}),
 'get_measures': ROW({'component': COMPONENT, 'missingMetrics': array(SHORT, 32), 'snapshot': SHORT}),
 'list_file_measures': ROW({'items': array(COMPONENT), 'total': lambda v: number(v, minimum=0),
   'page': number, 'pageSize': number, 'complete': boolean, 'snapshot': SHORT}),
 'get_duplications': ROW({'groups': array(array(ROW({'componentKey': T, 'from': number, 'size': number}), 100), 100),
                          'snapshot': SHORT}),
 'list_security_hotspots': ROW({'items': array(ROW({'key': ident, 'component': T, 'line': N(number),
    'message': T, 'status': SHORT, 'resolution': N(SHORT), 'securityCategory': N(SHORT),
    'vulnerabilityProbability': N(SHORT)})), 'total': lambda v: number(v, minimum=0),
    'page': number, 'pageSize': number, 'deprecated': boolean}),
 'get_security_hotspot': ROW({'key': ident, 'componentKey': T, 'message': T, 'status': SHORT,
    'resolution': N(SHORT), 'textRange': N(RANGE), 'ruleKey': ident,
    'riskDescription': lambda v: text(v, 12000), 'fixRecommendations': lambda v: text(v, 12000),
    'deprecated': boolean}),
}


def plain(value, limit=4000):
    text(value, limit * 2)
    # Render provider documentation as text; never execute provider HTML.
    value = re.sub(r'<(script|style)\b[^>]*>.*?</\1>', '', value, flags=re.I | re.S)
    return text(unescape(re.sub('<[^>]+>', '', value)), limit)


def validate_result(operation, result):
    ROW({'operation': SHORT, 'projectKey': ident, 'context': context,
         'data': SCHEMAS[operation]})(result)
    require(result['operation'] == operation)
    return result


def paging(raw, p, field):
    require(type(raw) is dict and type(raw.get(field)) is list and len(raw[field]) <= p['pageSize'])
    pg = raw.get('paging')
    ROW({'pageIndex': number, 'pageSize': number, 'total': lambda v: number(v, minimum=0)})(pg)
    require(pg['pageIndex'] == p['page'] and pg['pageSize'] == p['pageSize'])
    total = pg['total']; offset = (p['page'] - 1) * p['pageSize']; count = len(raw[field])
    require(offset + p['pageSize'] <= 10000, 'SONAR_PAGE_LIMIT')
    require(count == min(p['pageSize'], max(0, total - offset)), 'SONAR_PAGE_INCOMPLETE')
    return total, offset + count < total


def issue(raw, key):
    require(type(raw) is dict and raw.get('project') == key, 'SONAR_ISSUE_SCOPE_MISMATCH')
    out = {k: raw.get(k) for k in ('key', 'project', 'component', 'rule', 'message',
            'severity', 'type', 'line', 'textRange', 'effort', 'assignee', 'updateDate', 'creationDate')}
    require(type(out['component']) is str and out['component'].startswith(key + ':'))
    out['status'] = raw.get('issueStatus', raw.get('status'))
    out['tags'] = raw.get('tags', [])
    out['impacts'] = [project(x, {'softwareQuality': SHORT, 'severity': SHORT}) for x in raw.get('impacts', [])]
    out['flows'] = []
    for flow in array(lambda x: x, 20)(raw.get('flows', [])):
        require(type(flow) is dict)
        locations = array(lambda x: x, 50)(flow.get('locations'))
        for loc in locations:
            require(type(loc) is dict and type(loc.get('component')) is str and loc['component'].startswith(key + ':'))
        out['flows'].append([project(x, {'component': T, 'msg': N(T), 'textRange': N(RANGE)}) for x in locations])
    out['comments'] = [{'key': x.get('key'), 'text': x['markdown'] if type(x.get('markdown')) is str else plain(x.get('htmlText', '')),
                        'createdAt': x.get('createdAt')} for x in array(lambda x: x, 100)(raw.get('comments', []))]
    out['transitions'] = raw.get('transitions', [])
    return ISSUE(out)


class AnalysisReader:
    def __init__(self, parent):
        self.parent = parent

    def get(self, path, params):
        require(path in GET_ROUTES and set(params) <= GET_ROUTES[path], 'SONAR_ANALYSIS_ROUTE_DENIED')
        return self.parent._reader.call('GET', path, params)

    def _issue(self, key, issue_key, ctx):
        raw = self.get('/api/issues/search', dict(componentKeys=key, issues=issue_key, p='1', ps='2',
                      additionalFields='comments,transitions', **ctx))
        require(type(raw) is dict and type(raw.get('issues')) is list and len(raw['issues']) == 1)
        row = issue(raw['issues'][0], key)
        require(row['key'] == issue_key, 'SONAR_ISSUE_MISMATCH')
        return row

    @staticmethod
    def component(raw, key, requested):
        require(type(raw) is dict and type(raw.get('key')) is str and
                (raw['key'] == key or raw['key'].startswith(key + ':')))
        rows = array(lambda x: x, 32)(raw.get('measures', [])); measures = []
        seen = set()
        for x in rows:
            require(type(x) is dict and x.get('metric') in requested and x['metric'] not in seen)
            seen.add(x['metric'])
            period = x.get('period')
            new_value = period.get('value') if type(period) is dict else None
            if new_value is None and type(x.get('periods')) is list and x['periods']:
                new_value = x['periods'][0].get('value')
            value = x.get('value')
            measures.append(MEASURE(dict(metric=x['metric'], value=value, newValue=new_value,
              bestValue=x.get('bestValue'), dataState='NO_VALUE' if value is None and new_value is None else 'PRESENT')))
        return COMPONENT(dict(key=raw['key'], path=raw.get('path'), name=raw.get('name', raw['key']), measures=measures))

    def read(self, req):
        op, p = req['operation'], req['params']
        key = self.parent._check_project(req['target']); ctx = p.get('context', {})
        snapshot = 'CURRENT_CONTEXT_NOT_HISTORICAL_NOT_ATOMIC'
        if op in ('list_project_branches', 'list_project_pull_requests'):
            route, field = ('/api/project_branches/list', 'branches') if op == 'list_project_branches' else ('/api/project_pull_requests/list', 'pullRequests')
            raw = self.get(route, {'project': key})
            require(type(raw) is dict)
            data = {'items': [project(x, {k: SC for k, SC in (
                [('name', SHORT), ('isMain', boolean), ('type', N(SHORT)), ('analysisDate', N(SHORT))]
                if field == 'branches' else [('key', ident), ('branch', SHORT), ('base', SHORT), ('analysisDate', N(SHORT))])})
                for x in array(lambda x: x, 1000)(raw.get(field))]}
        elif op == 'list_analyses':
            raw = self.get('/api/project_analyses/search', dict(project=key, p=str(p['page']), ps=str(p['pageSize']), **ctx))
            total, more = paging(raw, p, 'analyses')
            data = dict(items=[project(x, {'key': ident, 'date': SHORT, 'revision': N(SHORT), 'buildString': N(SHORT)})
                        for x in raw['analyses']], total=total, page=p['page'], pageSize=p['pageSize'], complete=not more)
        elif op == 'get_analysis_task':
            raw = self.get('/api/ce/task', {'id': p['taskId'], 'additionalFields': 'warnings'})
            require(type(raw) is dict and type(raw.get('task')) is dict)
            task = raw['task']
            require(task.get('id') == p['taskId'] and task.get('componentKey') == key, 'SONAR_TASK_SCOPE_MISMATCH')
            data = {k: task.get(k) for k in ('id', 'componentKey', 'analysisId', 'status',
                    'submittedAt', 'startedAt', 'executedAt', 'errorMessage')}
            data['warnings'] = task.get('warnings', [])
        elif op == 'get_quality_gate_details':
            analysis_id = p['analysisId']
            if analysis_id:
                # V1 does not return project identity for analysisId. Membership must
                # be established from a project-scoped history before this lookup.
                found = False
                if 'taskId' in p:
                    task_response = self.get('/api/ce/task', {'id': p['taskId']})
                    require(type(task_response) is dict and type(task_response.get('task')) is dict)
                    task = task_response['task']
                    found = (task.get('id') == p['taskId'] and task.get('componentKey') == key and
                             task.get('status') == 'SUCCESS' and task.get('analysisId') == analysis_id)
                    require(found, 'SONAR_ANALYSIS_TASK_BINDING_MISMATCH')
                for n in ([] if found else range(1, 11)):
                    raw = self.get('/api/project_analyses/search', {'project': key, 'p': str(n), 'ps': '100'})
                    require(type(raw) is dict and type(raw.get('analyses')) is list and len(raw['analyses']) <= 100)
                    if any(x.get('key') == analysis_id for x in raw['analyses']): found = True; break
                    if len(raw['analyses']) < 100: break
                require(found, 'SONAR_ANALYSIS_MEMBERSHIP_UNVERIFIED')
                query = {'analysisId': analysis_id}
            else:
                query = dict(projectKey=key, **ctx)
            raw = self.get('/api/qualitygates/project_status', query)
            require(type(raw) is dict and type(raw.get('projectStatus')) is dict)
            qg = raw['projectStatus']; conditions = []
            for row in array(lambda x: x)(qg.get('conditions')):
                require(type(row) is dict)
                conditions.append(dict(status=row.get('status'), metricKey=row.get('metricKey'),
                  comparator=row.get('comparator'), actualValue=row.get('actualValue'),
                  errorThreshold=row.get('errorThreshold'),
                  dataState='NO_VALUE' if row.get('actualValue') is None else 'PRESENT'))
            data = dict(analysisId=analysis_id, status=qg.get('status'), conditions=conditions,
              ignoredConditions=qg.get('ignoredConditions'), binding='ANALYSIS_ID' if analysis_id else 'CONTEXT_ONLY',
              snapshot='ANALYSIS_GATE_WITH_CURRENT_TRIAGE' if analysis_id else snapshot)
        elif op in ('get_issue_details', 'get_issue_history'):
            row = self._issue(key, p['issueKey'], ctx)
            if op == 'get_issue_details': data = dict(issue=row, snapshot=snapshot)
            else:
                raw = self.get('/api/issues/changelog', {'issue': row['key']})
                require(type(raw) is dict)
                data = dict(issueKey=row['key'], changes=[dict(creationDate=x.get('creationDate'),
                    diffs=[project(d, {'key': SHORT, 'oldValue': N(T), 'newValue': N(T)}) for d in x.get('diffs', [])])
                    for x in array(lambda x: x, 200)(raw.get('changelog'))], snapshot=snapshot)
        elif op == 'search_issues':
            filters = {k: ','.join(v) for k, v in p['filters'].items() if k != 'newCodeOnly'}
            if 'newCodeOnly' in p['filters']: filters['sinceLeakPeriod'] = str(p['filters']['newCodeOnly']).lower()
            raw = self.get('/api/issues/search', dict(componentKeys=key, p=str(p['page']), ps=str(p['pageSize']),
                           additionalFields='comments,transitions', **ctx, **filters))
            total, more = paging(raw, p, 'issues')
            rows = [issue(x, key) for x in raw['issues']]
            require(len({x['key'] for x in rows}) == len(rows), 'SONAR_DUPLICATE_ISSUES')
            data = dict(issues=rows, total=total, page=p['page'], pageSize=p['pageSize'], hasMore=more,
                        nextPage=p['page'] + 1 if more and p['page'] * p['pageSize'] < 10000 else None, snapshot=snapshot)
        elif op == 'get_rule':
            raw = self.get('/api/rules/show', dict(key=p['ruleKey'], **({'contextKey': p['contextKey']} if 'contextKey' in p else {})))
            require(type(raw) is dict and type(raw.get('rule')) is dict)
            row = raw['rule']; require(row.get('key') == p['ruleKey'])
            description = row.get('htmlDesc', row.get('mdDesc', ''))
            if not description:
                description = '\n'.join(x.get('content', '') for x in row.get('descriptionSections', []))
            data = dict(key=row['key'], name=row.get('name'), description=plain(description, 24000),
                language=row.get('lang'), severity=row.get('severity'), type=row.get('type'),
                status=row.get('status'), tags=row.get('tags', []))
        elif op in ('get_measures', 'list_file_measures'):
            query = dict(component=key, metricKeys=','.join(p['metricKeys']), **ctx)
            if op == 'get_measures':
                raw = self.get('/api/measures/component', query)
                require(type(raw) is dict)
                require(type(raw.get('component')) is dict and raw['component'].get('key') == key)
                component = self.component(raw.get('component'), key, p['metricKeys'])
                data = dict(component=component, missingMetrics=sorted(set(p['metricKeys']) -
                   {x['metric'] for x in component['measures']}), snapshot=snapshot)
            else:
                raw = self.get('/api/measures/component_tree', dict(query, p=str(p['page']), ps=str(p['pageSize']),
                       qualifiers='FIL', strategy='leaves'))
                total, more = paging(raw, p, 'components')
                data = dict(items=[self.component(x, key, p['metricKeys']) for x in raw['components']],
                   total=total, page=p['page'], pageSize=p['pageSize'], complete=not more, snapshot=snapshot)
        elif op == 'get_duplications':
            raw = self.get('/api/duplications/show', dict(key=p['componentKey'], **ctx))
            require(type(raw) is dict and type(raw.get('files')) is dict)
            groups = []
            for group in array(lambda x: x)(raw.get('duplications')):
                blocks = []
                for block in array(lambda x: x)(group.get('blocks')):
                    f = raw['files'].get(block.get('_ref'))
                    require(type(f) is dict and type(f.get('key')) is str and f['key'].startswith(key + ':'), 'SONAR_DUPLICATION_SCOPE')
                    blocks.append(dict(componentKey=f['key'], **{k: block.get(k) for k in ('from', 'size')}))
                groups.append(blocks)
            data = dict(groups=groups, snapshot=snapshot)
        elif op == 'list_security_hotspots':
            raw = self.get('/api/hotspots/search', dict(projectKey=key, p=str(p['page']), ps=str(p['pageSize'])))
            total, _ = paging(raw, p, 'hotspots'); rows = []
            for x in raw['hotspots']:
                require(x.get('project') == key and x.get('component', '').startswith(key + ':'), 'SONAR_HOTSPOT_SCOPE')
                rows.append(project(x, {'key': ident, 'component': T, 'line': N(number), 'message': T,
                    'status': SHORT, 'resolution': N(SHORT), 'securityCategory': N(SHORT), 'vulnerabilityProbability': N(SHORT)}))
            data = dict(items=rows, total=total, page=p['page'], pageSize=p['pageSize'], deprecated=True)
        elif op == 'get_security_hotspot':
            raw = self.get('/api/hotspots/show', {'hotspot': p['hotspotKey']})
            require(type(raw) is dict and raw.get('key') == p['hotspotKey'] and raw.get('project', {}).get('key') == key)
            component = raw.get('component', {}).get('key')
            require(type(component) is str and component.startswith(key + ':'), 'SONAR_HOTSPOT_SCOPE')
            rule = raw.get('rule'); require(type(rule) is dict)
            data = dict(key=raw['key'], componentKey=component, message=raw.get('message'), status=raw.get('status'),
                resolution=raw.get('resolution'), textRange=raw.get('textRange'), ruleKey=rule.get('key'),
                riskDescription=plain(rule.get('riskDescription', ''), 12000),
                fixRecommendations=plain(rule.get('fixRecommendations', ''), 12000), deprecated=True)
        else:
            raise Denied('SONAR_ANALYSIS_READ_DENIED')
        result = dict(operation=op, projectKey=key, context=ctx, data=data)
        return validate_result(op, result)
