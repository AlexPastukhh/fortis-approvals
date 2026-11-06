"""Closed CI inspection/control operations, enabled only by trusted review config."""
from ..review_schema import (require, text, number, sha, fields, object_schema, array,
                            nullable, boolean, context, ident)

READ_NAMES = frozenset({'get_workflow_run', 'list_workflow_jobs', 'get_job_log',
    'get_check_run', 'list_check_annotations', 'list_run_artifacts', 'get_analysis_manifest'})
ACTION_NAMES = frozenset({'rerun_failed_jobs', 'rerun_job', 'cancel_analysis_run', 'dispatch_analysis_workflow'})
READS = frozenset(('github', x) for x in READ_NAMES)
ACTIONS = frozenset(('github', x) for x in ACTION_NAMES)
T = lambda x: text(x, 4000)
S = lambda x: text(x, 200)
N = nullable
ROW = object_schema
RUN = ROW({'id': number, 'attempt': number, 'workflowId': number, 'workflowPath': S,
    'event': S, 'status': S, 'conclusion': N(S), 'headSha': sha, 'headBranch': S,
    'repository': S, 'headRepository': S, 'createdAt': S, 'updatedAt': S,
    'pullRequests': array(ROW({'number': number, 'headSha': sha, 'baseSha': sha}), 100)})
STEP = ROW({'number': number, 'name': S, 'status': S, 'conclusion': N(S)})
JOB = ROW({'id': number, 'name': S, 'status': S, 'conclusion': N(S), 'steps': array(STEP, 200)})
ARTIFACT = ROW({'id': number, 'name': S, 'size': lambda x: number(x, minimum=0),
    'expired': boolean, 'digest': N(S), 'createdAt': S})
CHECK = ROW({'id': number, 'name': S, 'headSha': sha, 'status': S, 'conclusion': N(S),
    'appId': number, 'appSlug': S, 'title': N(T), 'summary': N(lambda x: text(x, 16000)),
    'text': N(lambda x: text(x, 16000)), 'annotationCount': lambda x: number(x, minimum=0)})
ANNOTATION = ROW({'path': T, 'startLine': number, 'endLine': number, 'level': S, 'message': T, 'title': N(S)})
MANIFEST = ROW({'schemaVersion': lambda x: require(type(x) is int and x == 1) or x,
    'repository': S, 'workflowId': number, 'workflowPath': S, 'runId': number,
    'attempt': number, 'projectKey': ident, 'context': context, 'prHeadSha': N(sha),
    'checkoutSha': sha, 'scannerRevision': sha, 'ceTaskId': ident})
SCHEMAS = {
 'get_workflow_run': ROW({'run': RUN}),
 'list_workflow_jobs': ROW({'run': RUN, 'items': array(JOB), 'total': lambda x: number(x, minimum=0),
                            'page': number, 'perPage': number, 'complete': boolean}),
 'get_job_log': ROW({'run': RUN, 'jobId': number, 'offsetLines': lambda x: number(x, minimum=0),
    'text': lambda x: text(x, 64000), 'hasMore': boolean, 'redacted': boolean}),
 'get_check_run': ROW({'check': CHECK}),
 'list_check_annotations': ROW({'check': CHECK, 'items': array(ANNOTATION), 'page': number,
                                'perPage': number, 'complete': boolean}),
 'list_run_artifacts': ROW({'run': RUN, 'items': array(ARTIFACT), 'total': lambda x: number(x, minimum=0),
                            'page': number, 'perPage': number, 'complete': boolean}),
 'get_analysis_manifest': ROW({'run': RUN, 'artifactId': number, 'manifest': MANIFEST,
                               'trust': S}),
}


def validate_read(op, p):
    if op in ('get_workflow_run',):
        fields(p, ('runId', 'attempt'))
    elif op in ('list_workflow_jobs', 'list_run_artifacts'):
        fields(p, ('runId', 'attempt', 'page', 'perPage'))
    elif op == 'get_job_log':
        fields(p, ('runId', 'attempt', 'jobId', 'offsetLines', 'maxLines'))
        number(p['offsetLines'], 200000, 0); number(p['maxLines'], 500)
    elif op == 'get_analysis_manifest':
        fields(p, ('runId', 'attempt', 'artifactId'))
    elif op in ('get_check_run', 'list_check_annotations'):
        fields(p, ('checkRunId', 'expectedHeadSha') + (('page', 'perPage') if op == 'list_check_annotations' else ()))
        sha(p['expectedHeadSha'])
    else:
        require(False, 'GITHUB_ANALYSIS_READ_DENIED')
    for key in ('runId', 'attempt', 'jobId', 'artifactId', 'checkRunId'):
        if key in p: number(p[key])
    if 'page' in p:
        number(p['page'], 100); number(p['perPage'], 100)
    return p


def validate_action(op, p):
    if op == 'dispatch_analysis_workflow':
        fields(p, ('workflowId', 'ref', 'expectedHeadSha'))
        from .contract import _branch
        _branch(p['ref']); number(p['workflowId'])
    else:
        fields(p, ('runId', 'attempt', 'expectedHeadSha') + (('jobId',) if op == 'rerun_job' else ()))
        number(p['runId']); number(p['attempt'])
        if op == 'rerun_job': number(p['jobId'])
    sha(p['expectedHeadSha'])
    return p


def validate_result(op, result):
    ROW({'operation': S, 'data': SCHEMAS[op]})(result)
    require(result['operation'] == op)
    return result
