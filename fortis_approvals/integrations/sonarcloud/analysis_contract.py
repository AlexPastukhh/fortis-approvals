"""Analysis review catalogue. Registration never grants these operations."""
from ..review_schema import (require, text, ident, number, context, page, fields)

READ_NAMES = frozenset({
    'list_project_branches', 'list_project_pull_requests', 'list_analyses',
    'get_analysis_task', 'get_quality_gate_details', 'search_issues',
    'get_issue_details', 'get_rule', 'get_measures', 'list_file_measures',
    'get_duplications', 'get_issue_history', 'list_security_hotspots',
    'get_security_hotspot',
})
ACTION_NAMES = frozenset({
    'mark_false_positive', 'reopen_issue', 'confirm_issue', 'add_issue_comment',
    'assign_issue', 'set_issue_tags',
})
READS = frozenset(('sonarcloud', x) for x in READ_NAMES)
ACTIONS = frozenset(('sonarcloud', x) for x in ACTION_NAMES)
TRANSITIONS = {'mark_false_positive': ('falsepositive', 'FALSE_POSITIVE'),
               'reopen_issue': ('reopen', 'OPEN'), 'confirm_issue': ('confirm', 'CONFIRMED'),
               'accept_issue': ('accept', 'ACCEPTED')}
GET_ROUTES = {
    '/api/ce/task': {'id', 'additionalFields'},
    '/api/project_analyses/search': {'project', 'branch', 'p', 'ps'},
    '/api/project_branches/list': {'project'},
    '/api/project_pull_requests/list': {'project'},
    '/api/qualitygates/project_status': {'projectKey', 'branch', 'pullRequest', 'analysisId'},
    '/api/issues/search': {'componentKeys', 'branch', 'pullRequest', 'issues', 'p', 'ps',
        'additionalFields', 'issueStatuses', 'impactSeverities', 'impactSoftwareQualities',
        'rules', 'types', 'sinceLeakPeriod', 'facets', 's', 'asc'},
    '/api/issues/changelog': {'issue'},
    '/api/rules/show': {'key', 'contextKey'},
    '/api/measures/component': {'component', 'branch', 'pullRequest', 'metricKeys', 'additionalFields'},
    '/api/measures/component_tree': {'component', 'branch', 'pullRequest', 'metricKeys',
        'p', 'ps', 'qualifiers', 'strategy'},
    '/api/duplications/show': {'key', 'branch', 'pullRequest'},
    '/api/hotspots/search': {'projectKey', 'p', 'ps'},
    '/api/hotspots/show': {'hotspot'},
}
POST_ROUTES = {
    '/api/issues/do_transition': {'issue', 'transition', 'comment'},
    '/api/issues/add_comment': {'issue', 'text'},
    '/api/issues/assign': {'issue', 'assignee'},
    '/api/issues/set_tags': {'issue', 'tags'},
}
METRICS = frozenset({
    'coverage', 'line_coverage', 'branch_coverage', 'uncovered_lines', 'uncovered_conditions',
    'lines_to_cover', 'conditions_to_cover', 'new_coverage', 'new_line_coverage',
    'new_branch_coverage', 'new_uncovered_lines', 'new_uncovered_conditions',
    'new_lines_to_cover', 'new_conditions_to_cover', 'duplicated_lines_density',
    'duplicated_blocks', 'duplicated_lines', 'new_duplicated_lines_density',
    'new_duplicated_lines', 'ncloc', 'new_lines', 'complexity', 'cognitive_complexity',
    'reliability_rating', 'security_rating', 'sqale_rating', 'new_reliability_rating',
    'new_security_rating', 'new_maintainability_rating', 'security_hotspots_reviewed',
    'new_security_hotspots_reviewed', 'violations', 'bugs', 'vulnerabilities', 'code_smells',
})


def validate_read(operation, target, p):
    ident(target)
    if operation in ('list_project_branches', 'list_project_pull_requests'):
        fields(p, ())
    elif operation == 'get_analysis_task':
        fields(p, ('taskId',)); ident(p['taskId'])
    elif operation == 'get_rule':
        fields(p, ('ruleKey',), ('contextKey',)); ident(p['ruleKey'])
        if 'contextKey' in p: text(p['contextKey'], 200, empty=False)
    elif operation in ('get_issue_details', 'get_issue_history'):
        fields(p, ('issueKey', 'context')); ident(p['issueKey']); context(p['context'])
    elif operation == 'get_security_hotspot':
        fields(p, ('hotspotKey',)); ident(p['hotspotKey'])
    elif operation == 'list_security_hotspots':
        fields(p, ('page', 'pageSize')); page(p)
    elif operation == 'get_quality_gate_details':
        fields(p, ('context', 'analysisId'), ('taskId',)); context(p['context'])
        if 'taskId' in p:
            ident(p['taskId']); require(p['analysisId'] is not None)
        if p['analysisId'] is not None:
            ident(p['analysisId'])
            require(not p['context'], 'SONAR_ANALYSIS_AND_CONTEXT_EXCLUSIVE')
    elif operation == 'get_duplications':
        fields(p, ('context', 'componentKey')); context(p['context'])
        text(p['componentKey'], 500, empty=False)
        require(p['componentKey'].startswith(target + ':'))
    elif operation in ('get_measures', 'list_file_measures'):
        fields(p, ('context', 'metricKeys') + (('page', 'pageSize') if operation == 'list_file_measures' else ()))
        context(p['context'])
        require(type(p['metricKeys']) is list and 1 <= len(p['metricKeys']) <= 32 and
                all(type(x) is str and x in METRICS for x in p['metricKeys']) and
                len(set(p['metricKeys'])) == len(p['metricKeys']))
        if operation == 'list_file_measures': page(p)
    elif operation in ('list_analyses', 'search_issues'):
        fields(p, ('context', 'page', 'pageSize') + (('filters',) if operation == 'search_issues' else ()))
        context(p['context']); page(p)
        if operation == 'list_analyses':
            require('pullRequest' not in p['context'], 'SONAR_PR_HISTORY_UNAVAILABLE')
        else:
            filters = p['filters']
            fields(filters, (), ('issueStatuses', 'impactSeverities', 'impactSoftwareQualities', 'rules', 'types', 'newCodeOnly'))
            enums = {'issueStatuses': {'OPEN', 'CONFIRMED', 'FALSE_POSITIVE', 'ACCEPTED', 'FIXED'},
                     'impactSeverities': {'INFO', 'LOW', 'MEDIUM', 'HIGH', 'BLOCKER'},
                     'impactSoftwareQualities': {'MAINTAINABILITY', 'RELIABILITY', 'SECURITY'},
                     'types': {'CODE_SMELL', 'BUG', 'VULNERABILITY'}}
            for k, v in filters.items():
                if k == 'newCodeOnly': require(type(v) is bool)
                else:
                    require(type(v) is list and 1 <= len(v) <= 20)
                    for item in v:
                        ident(item)
                        if k in enums: require(item in enums[k])
    else:
        require(False, 'SONAR_ANALYSIS_OPERATION_DENIED')
    return p


def validate_action(operation, target, p):
    ident(target); fields(p, ('projectKey',), ('comment', 'assignee', 'tags'))
    ident(p['projectKey'])
    allowed = {'projectKey'}
    if operation in TRANSITIONS or operation == 'add_issue_comment': allowed.add('comment')
    if operation == 'assign_issue': allowed.add('assignee')
    if operation == 'set_issue_tags': allowed.add('tags')
    require(set(p) <= allowed)
    if 'comment' in p: text(p['comment'], 2000, empty=False)
    if operation == 'add_issue_comment': require('comment' in p)
    if operation == 'assign_issue':
        require('assignee' in p)
        text(p['assignee'], 100)
        require(all(ord(c) >= 32 for c in p['assignee']))
    if operation == 'set_issue_tags':
        tags = p.get('tags')
        require(type(tags) is list and len(tags) <= 20 and all(type(x) is str for x in tags))
        require(len(set(tags)) == len(tags))
        for tag in tags:
            text(tag, 50, empty=False)
            require(all(c.isalnum() or c in '-_.' for c in tag))
    return p
