"""Bounded OpenAPI drafts: no network, no grants, no automatic trust."""
from copy import deepcopy
import json
from types import SimpleNamespace
from tempfile import TemporaryDirectory
from pathlib import Path
import unittest
from unittest.mock import patch

from fortis_approvals.core import Denied
from fortis_approvals.extensions.declarative_read import compile_read_provider
from fortis_approvals.extensions.http import JSONAPI, Route
from fortis_approvals.extensions.openapi_intake import (inspect_openapi,
                                                       bind_source_draft)
from fortis_approvals.extensions.source_generator import render_package
from fortis_approvals.extensions.source_strategy import advise_onboarding
from fortis_approvals.extensions import source_onboarding
from fortis_approvals.tests.test_source_strategy import evidence
from fortis_approvals.tests.test_source_generator import record_description
from fortis_approvals.tests.test_declarative_read import action_sample


def object_schema(*,extra=False):
    return {'type':'object','required':['action_id','name','schedule_active'],
            'properties':{
             'action_id':{'type':'integer','minimum':1,'maximum':100},
             'name':{'type':'string','minLength':1,'maxLength':200},
             'schedule_active':{'type':'boolean'},
             'additionalSecret':{'type':'string','maxLength':100}},
            'additionalProperties':bool(extra)}


def spec_30():
    return {'openapi':'3.0.3','info':{'title':'Action records','version':'v1'},
        'servers':[{'url':'http://untrusted-no-execution.invalid'}],
        'paths':{'/v1/records/{action_id}':{'get':{
            'operationId':'read_action',
            'parameters':[{'name':'action_id','in':'path','required':True,
                           'schema':{'type':'integer','format':'int64'}}],
            'responses':{'200':{'description':'ok','content':{
                'application/json':{'schema':object_schema()}}},
                '404':{'description':'not found'}}}}}}


def spec_31():
    return {'openapi':'3.1.2','info':{'title':'User sessions','version':'2'},
        'components':{'schemas':{
            'Session':{'type':'object','required':['session_id','active'],
                       'properties':{
                          'session_id':{'type':['string','null'],'minLength':1,
                                        'maxLength':40},
                          'active':{'type':'boolean'},
                          'optional_private':{'type':'string','maxLength':300}}},
            'List':{'type':'object','required':['items','ok'],
                    'properties':{'ok':{'type':'boolean'},
                    'items':{'type':'array','maxItems':30,
                             'items':{'$ref':'#/components/schemas/Session'}}}}}},
        'paths':{'/v2/sessions':{'get':{
            'operationId':'list_sessions',
            'parameters':[{'name':'offset','in':'query','required':False,
                         'schema':{'type':'integer','minimum':0,'maximum':500}}],
            'responses':{'200':{'content':{'application/json':{
                    'schema':{'$ref':'#/components/schemas/List'}}}}}}}}}


def bind(plan,targets=None,selected=None,origin='https://trusted.example.invalid'):
    if targets is None:targets={'read_action':['3','4']}
    return bind_source_draft(plan,origin,targets,selected=selected)


def compile_bound_source(source):
    routes = tuple(Route(row['name'], 'GET', row['path'], readonly=True,
                         query_keys=tuple(row['queryKeys'])) for row in source['routes'])
    return compile_read_provider(source['provider'], JSONAPI(source['origin'], routes),
                                 tuple(source['methods']))


class OpenAPIIntakeTests(unittest.TestCase):
    def test_openapi_30_source_plan_is_unreviewed_and_never_trusts_servers(self):
        plan=inspect_openapi(spec_30(),'study_records')
        self.assertEqual(plan['status'],'REVIEW_REQUIRED')
        self.assertIs(plan['reviewed'],False)
        self.assertEqual(plan['operations'][0]['status'],'DRAFT_COMPILABLE')
        self.assertEqual(plan['operations'][0]['sourceMethod']['targets'],[])
        self.assertIsNone(plan['sourceTemplate']['origin'])
        self.assertEqual(plan['sourceTemplate']['routes'][0]['path'],
                         '/v1/records/{action_id}')
        self.assertEqual(plan['sourceTemplate']['methods'][0]['projection'],
                         {'action_id':'action_id','name':'name',
                          'schedule_active':'schedule_active'})
        self.assertNotIn('additionalSecret',plan['sourceTemplate']['methods'][0]['resultSchema']['fields'])
        self.assertNotIn('untrusted-no-execution',json.dumps(plan))

    def test_explicit_bind_produces_genuine_source_compiler_descriptor(self):
        plan=inspect_openapi(spec_30(),'study_records')
        result=bind(plan)
        self.assertEqual(result['status'],'REVIEW_REQUIRED')
        self.assertIs(result['reviewed'],False)
        code=render_package(result['sourceDescription'])
        self.assertEqual(len(code),5)
        method=result['sourceDescription']['methods'][0]
        self.assertEqual(method['targets'],['3','4'])
        self.assertNotIn('authorization',json.dumps(result).lower())

    def test_explicit_source_review_can_continue_through_existing_onboarding(self):
        # The importer does NOT set reviewed=true: it is supplied here as a
        # separate fixture simulating independently verified API evidence.
        result=bind(inspect_openapi(spec_30(),'study_records'))
        source=result['sourceDescription']
        facts=evidence(reviewed=False)
        self.assertEqual(advise_onboarding(facts,source)['status'],'REVIEW_REQUIRED')
        facts['reviewed']=True
        self.assertEqual(advise_onboarding(facts,source)['status'],
                         'SOURCE_PREFLIGHT_READY')
        with TemporaryDirectory(prefix='openapi-task-') as temporary:
            session=Path(temporary)
            checkpoint=source_onboarding.begin(session,facts,source)
            self.assertEqual(checkpoint['phase'],'SOURCE_READY')
            self.assertFalse((session/'fortis_approvals').exists())
            self.assertEqual(source_onboarding.inspect(session)['phase'],'SOURCE_READY')

    def test_openapi_31_local_refs_nullable_array_projection(self):
        plan=inspect_openapi(spec_31(),'study_sessions')
        self.assertEqual(plan['operations'][0]['status'],'DRAFT_COMPILABLE')
        row=plan['sourceTemplate']['methods'][0]
        self.assertEqual(row['resultSchema']['fields']['items']['maxItems'],30)
        self.assertEqual(row['resultSchema']['fields']['items']['items']['fields']['session_id']['type'],
                         'nullable')
        self.assertEqual(row['projection']['items'],{
            'array':'items','fields':{'active':'active','session_id':'session_id'}})
        linked=bind(plan,{'list_sessions':['registry']})
        self.assertEqual(linked['sourceDescription']['routes'][0]['queryKeys'],['offset'])

    def test_31_optional_query_uses_nullable_binding_but_no_default_url(self):
        plan=inspect_openapi(spec_31(),'study_sessions')
        row=plan['sourceTemplate']['methods'][0]
        self.assertEqual(row['paramsSchema']['fields']['offset']['type'],'nullable')
        self.assertEqual(row['query'],{'offset':'offset'})
        self.assertIsNone(plan['sourceTemplate']['origin'])

    def test_method_with_missing_operation_id_is_deterministically_named(self):
        spec=spec_30();spec['paths']['/v1/records/{action_id}']['get'].pop('operationId')
        a=inspect_openapi(spec,'study_records')
        b=inspect_openapi(deepcopy(spec),'study_records')
        self.assertTrue(a['operations'][0]['name'].startswith('get_'))
        self.assertEqual(a,b)

    def test_write_and_read_in_same_spec_requires_explicit_method_selection(self):
        spec=spec_30()
        spec['paths']['/v1/records/{action_id}']['post']={
            'operationId':'write_action','responses':{'200':{'description':'created'}}}
        plan=inspect_openapi(spec,'study_records')
        by_id={x['name']:x for x in plan['operations']}
        self.assertEqual(by_id['write_action']['reasonCodes'],
                         ['OPENAPI_WRITE_OR_NON_GET_REVIEW_REQUIRED'])
        self.assertEqual(by_id['read_action']['status'],'DRAFT_COMPILABLE')
        with self.assertRaisesRegex(Denied,'OPENAPI_EXPLICIT_METHOD_SELECTION_REQUIRED'):
            bind(plan)
        subset=bind(plan,selected=['read_action'])
        self.assertEqual(subset['excludedMethods'],['write_action'])
        self.assertEqual(len(subset['sourceDescription']['methods']),1)
        with self.assertRaisesRegex(Denied,'OPENAPI_SELECTION_INVALID'):
            bind(plan,selected=['write_action'])

    def test_never_performs_network_or_file_write_during_inspect(self):
        before=deepcopy(spec_30())
        import urllib.request
        with patch.object(urllib.request,'urlopen',side_effect=AssertionError('network forbidden')):
            plan=inspect_openapi(before,'study_records')
        self.assertEqual(before,spec_30())
        self.assertEqual(plan['status'],'REVIEW_REQUIRED')

    def test_invalid_versions_and_duplicate_json_fields_stop(self):
        with self.assertRaisesRegex(Denied,'OPENAPI_DOCUMENT_UNSUPPORTED'):
            inspect_openapi({'openapi':'2.0','paths':{'/':{}},'info':{}},'study_records')
        bad='{"openapi":"3.0.3","openapi":"3.1.0","info":{},"paths":{"/v1":{}}}'
        with self.assertRaisesRegex(Denied,'OPENAPI_DOCUMENT_INVALID_JSON'):
            inspect_openapi(bad,'study_records')

    def test_document_size_limit_and_local_ref_cycle_stop(self):
        too_big=spec_30();too_big['info']['description']='x'*263000
        with self.assertRaisesRegex(Denied,'OPENAPI_DOCUMENT_TOO_LARGE'):
            inspect_openapi(too_big,'study_records')
        cycle=spec_31();cycle['components']['schemas']['Session']={
            '$ref':'#/components/schemas/Session'}
        plan=inspect_openapi(cycle,'study_sessions')
        self.assertIn('OPENAPI_REFERENCE_CYCLE_OR_DEPTH',
                      plan['operations'][0]['reasonCodes'])

    def test_external_and_complex_refs_rejected_without_fetch(self):
        for ref in ('https://evil.invalid/schema.json',
                    '../other.json#/components/schemas/Session',
                    '#/components/schemas/Session/properties/active'):
            spec=spec_31();spec['components']['schemas']['List']['properties']['items']['items']={'$ref':ref}
            with self.subTest(ref=ref):
                row=inspect_openapi(spec,'study_sessions')['operations'][0]
                self.assertEqual(row['status'],'REVIEW_REQUIRED')
                self.assertIn('OPENAPI_EXTERNAL_OR_COMPLEX_REF_UNSUPPORTED',row['reasonCodes'])

    def test_missing_max_length_and_array_bound_require_manual_review(self):
        spec=spec_30();spec['paths']['/v1/records/{action_id}']['get']['responses']['200']['content']['application/json']['schema']['properties']['name'].pop('maxLength')
        row=inspect_openapi(spec,'study_records')['operations'][0]
        self.assertIn('OPENAPI_STRING_NEEDS_LENGTH_BOUNDS',row['reasonCodes'])
        spec=spec_31();spec['components']['schemas']['List']['properties']['items'].pop('maxItems')
        row=inspect_openapi(spec,'study_sessions')['operations'][0]
        self.assertIn('OPENAPI_ARRAY_NEEDS_BOUNDED_MAXITEMS',row['reasonCodes'])

    def test_unsupported_format_and_constraint_are_not_silently_lost(self):
        for change,reason in (({'format':'date-time'},'OPENAPI_STRING_FORMAT_REVIEW_REQUIRED'),
                              ({'pattern':'^[A-Z]+$'},'OPENAPI_SCHEMA_KEYWORD_UNSUPPORTED')):
            spec=spec_30()
            schema=spec['paths']['/v1/records/{action_id}']['get']['responses']['200']['content']['application/json']['schema']['properties']['name']
            schema.update(change)
            row=inspect_openapi(spec,'study_records')['operations'][0]
            self.assertIn(reason,row['reasonCodes'])

    def test_sensitive_required_response_and_query_params_rejected(self):
        spec=spec_30()
        schema=spec['paths']['/v1/records/{action_id}']['get']['responses']['200']['content']['application/json']['schema']
        schema['required'].append('token')
        schema['properties']['token']={'type':'string','maxLength':200}
        row=inspect_openapi(spec,'study_records')['operations'][0]
        self.assertIn('OPENAPI_SENSITIVE_OR_UNMAPPABLE_FIELD',row['reasonCodes'])
        spec=spec_31()
        spec['paths']['/v2/sessions']['get']['parameters'][0]['name']='authorization'
        row=inspect_openapi(spec,'study_sessions')['operations'][0]
        self.assertIn('OPENAPI_UNSAFE_PARAMETER_NAME',row['reasonCodes'])

    def test_header_params_get_body_and_path_override_stopped(self):
        for mode,reason in [('header','OPENAPI_HEADER_OR_COOKIE_PARAM_REVIEW_REQUIRED'),
                            ('body','OPENAPI_GET_REQUEST_BODY_UNSUPPORTED'),
                            ('server','OPENAPI_OPERATION_SERVER_OVERRIDE_REVIEW_REQUIRED')]:
            spec=spec_30()
            op=spec['paths']['/v1/records/{action_id}']['get']
            if mode=='header':op['parameters'].append({
                'name':'special_header','in':'header','schema':{'type':'string','maxLength':20}})
            elif mode=='body':op['requestBody']={'content':{}}
            else:op['servers']=[{'url':'https://another.invalid'}]
            row=inspect_openapi(spec,'study_records')['operations'][0]
            self.assertIn(reason,row['reasonCodes'])

    def test_path_control_and_multiple_placeholders_require_review(self):
        for changed in ('/v1/../admin','/v1/records/{one}/{two}',
                        '/v1/%2e%2e/admin'):
            spec=spec_30();spec['paths']={changed:next(iter(spec['paths'].values()))}
            row=inspect_openapi(spec,'study_records')['operations'][0]
            self.assertEqual(row['status'],'REVIEW_REQUIRED')

    def test_non_json_success_or_optional_required_fields_stop(self):
        spec=spec_30()
        obj=spec['paths']['/v1/records/{action_id}']['get']['responses']['200']
        obj['content']={'text/plain':{'schema':{'type':'string'}}}
        self.assertIn('OPENAPI_JSON_200_SCHEMA_REQUIRED',
                      inspect_openapi(spec,'study_records')['operations'][0]['reasonCodes'])
        spec=spec_30()
        schema=spec['paths']['/v1/records/{action_id}']['get']['responses']['200']['content']['application/json']['schema']
        schema['required']=[]
        self.assertIn('OPENAPI_REQUIRED_RESULT_FIELDS_UNAVAILABLE',
                      inspect_openapi(spec,'study_records')['operations'][0]['reasonCodes'])

    def test_compiled_source_projection_excludes_unreviewed_fields(self):
        source=bind(inspect_openapi(spec_30(),'study_records'))['sourceDescription']
        provider = compile_bound_source(source)
        class Fixture:
            target='3';params={}
            def call(self,route,**kwargs):
                assert route=='read_action'
                assert kwargs=={'path':{'action_id':'3'}}
                return {'action_id':3,'name':'Review fixture','schedule_active':False,
                        'additionalSecret':'not allowed into user result'}
        value=provider.operations[0].execute(Fixture())
        self.assertEqual(set(value),{'action_id','name','schedule_active'})
        self.assertNotIn('additionalSecret',value)

    def test_malformed_parameter_collections_stop_without_python_exception(self):
        for invalid in (None,{},'bad',99):
            spec=spec_30()
            spec['paths']['/v1/records/{action_id}']['get']['parameters']=invalid
            row=inspect_openapi(spec,'study_records')['operations'][0]
            self.assertIn('OPENAPI_PARAMETERS_INVALID',row['reasonCodes'])

    def test_required_schema_invalid_types_fail_as_review_not_python_type_error(self):
        for invalid in ([{}],[None],['name',{'field':'x'}],'abc',True):
            spec=spec_30()
            schema=spec['paths']['/v1/records/{action_id}']['get']['responses']['200']['content']['application/json']['schema']
            schema['required']=invalid
            row=inspect_openapi(spec,'study_records')['operations'][0]
            self.assertIn('OPENAPI_REQUIRED_RESULT_FIELDS_UNAVAILABLE',
                          row['reasonCodes'])

    def test_nullable_object_or_unsupported_union_does_not_get_dropped(self):
        for kind in (['null','null'],['integer','string','null'],
                     ['boolean','null','null']):
            spec=spec_30()
            schema=spec['paths']['/v1/records/{action_id}']['get']['responses']['200']['content']['application/json']['schema']
            schema['properties']['name']['type']=kind
            row=inspect_openapi(spec,'study_records')['operations'][0]
            self.assertEqual(row['status'],'REVIEW_REQUIRED')
            self.assertIn('OPENAPI_UNION_UNSUPPORTED',row['reasonCodes'])
        spec=spec_31()
        schema=spec['components']['schemas']['Session']
        schema['nullable']=True
        row=inspect_openapi(spec,'study_sessions')['operations'][0]
        self.assertIn('OPENAPI_NULLABLE_OBJECT_UNSUPPORTED',row['reasonCodes'])

    def test_write_only_field_never_becomes_a_projected_read_output(self):
        spec=spec_30()
        schema=spec['paths']['/v1/records/{action_id}']['get']['responses']['200']['content']['application/json']['schema']
        schema['properties']['name']['writeOnly']=True
        row=inspect_openapi(spec,'study_records')['operations'][0]
        self.assertIn('OPENAPI_WRITE_ONLY_RESPONSE_REVIEW_REQUIRED',row['reasonCodes'])

    def test_optional_auth_and_upstream_scopes_are_not_grants(self):
        spec=spec_30()
        spec['components']={'securitySchemes':{'gatewayAuth':{
             'type':'http','scheme':'bearer'}}}
        spec['security']=[{'gatewayAuth':[]}]
        plan=inspect_openapi(spec,'study_records')
        self.assertEqual(plan['operations'][0]['status'],'DRAFT_COMPILABLE')
        self.assertIsNone(plan['sourceTemplate']['methods'][0]['credential'])
        self.assertFalse(plan['reviewed'])
        self.assertIn('Review authorization and security schemes separately',
                      plan['reviewTasks'])

    def test_required_parameter_flag_invalid_is_review_not_guessed(self):
        spec=spec_30()
        spec['paths']['/v1/records/{action_id}']['get']['parameters'][0]['required']='yes'
        row=inspect_openapi(spec,'study_records')['operations'][0]
        self.assertIn('OPENAPI_PARAMETER_REQUIRED_INVALID',row['reasonCodes'])

    def test_additional_success_response_is_not_ignored(self):
        spec=spec_30()
        spec['paths']['/v1/records/{action_id}']['get']['responses']['206']={
            'description':'partial','content':{'application/json':{
                'schema':object_schema()}}}
        row=inspect_openapi(spec,'study_records')['operations'][0]
        self.assertIn('OPENAPI_ADDITIONAL_SUCCESS_RESPONSE_REVIEW_REQUIRED',
                      row['reasonCodes'])

    def test_nested_reference_cannot_force_reference_fetch(self):
        spec=spec_31()
        spec['components']['schemas']['Session']['properties']['session_id']={
            '$ref':'#/components/schemas/Missing'}
        row=inspect_openapi(spec,'study_sessions')['operations'][0]
        self.assertIn('OPENAPI_LOCAL_REFERENCE_MISSING',row['reasonCodes'])

    def test_bad_json_schema_types_are_rejected_without_tracebacks(self):
        variants=(None,[],True,{'type':[]},
                  {'type':'string','maxLength':'unknown'},
                  {'type':'string','maxLength':True},
                  {'type':'array','maxItems':True,'items':{'type':'integer'}},
                  {'type':'integer','minimum':False},
                  {'type':'integer','enum':[1,False]})
        for value in variants:
            with self.subTest(value=value):
                spec=spec_30()
                node=spec['paths']['/v1/records/{action_id}']['get']['responses']['200']['content']['application/json']['schema']['properties']
                node['name']=value
                row=inspect_openapi(spec,'study_records')['operations'][0]
                self.assertEqual(row['status'],'REVIEW_REQUIRED')
                self.assertTrue(row['reasonCodes'])

    def test_parameter_refs_stay_local_and_optional_query_is_bounded(self):
        spec=spec_30()
        spec['components']={'parameters':{'Limit':{'name':'limit','in':'query',
            'required':False,'schema':{'type':'integer','minimum':1,'maximum':50}}}}
        spec['paths']['/v1/records/{action_id}']['get']['parameters'].append(
            {'$ref':'#/components/parameters/Limit'})
        plan=inspect_openapi(spec,'study_records')
        self.assertEqual(plan['operations'][0]['status'],'DRAFT_COMPILABLE')
        params=plan['sourceTemplate']['methods'][0]['paramsSchema']['fields']
        self.assertEqual(params['limit']['item']['maximum'],50)
        self.assertEqual(plan['sourceTemplate']['routes'][0]['queryKeys'],['limit'])
        bound=bind(plan)
        render_package(bound['sourceDescription'])

    def test_bound_path_targets_must_satisfy_the_openapi_scalar_schema(self):
        cases = (
            ({'type': 'integer', 'minimum': 100, 'maximum': 200},
             ['100', '200'], ['abc', '99', '201', '0100']),
            ({'type': 'integer', 'format': 'int64'}, ['9223372036854775807'],
             ['abc', '9223372036854775808']),
            ({'type': 'string', 'minLength': 4, 'maxLength': 6},
             ['abcd', 'abcdef'], ['abc', 'abcdefg']),
        )
        for schema, valid, invalid in cases:
            spec = spec_30()
            parameter = spec['paths']['/v1/records/{action_id}']['get']['parameters'][0]
            parameter['schema'] = schema
            plan = inspect_openapi(spec, 'study_records')
            with self.subTest(schema=schema):
                bound = bind(plan, {'read_action': valid})
                operation = compile_bound_source(bound['sourceDescription']).operations[0]
                self.assertEqual(operation.allowed_targets, tuple(valid))
                with self.assertRaisesRegex(Denied, 'DECLARATIVE_TARGET_DENIED'):
                    operation.execute(SimpleNamespace(target=invalid[0]))
            for target in invalid:
                with self.subTest(schema=schema, target=target):
                    with self.assertRaisesRegex(Denied, 'OPENAPI_PATH_TARGET_SCHEMA_MISMATCH'):
                        bind(plan, {'read_action': [valid[0], target]})
        with self.assertRaisesRegex(Denied, 'OPENAPI_TARGET_BINDING_REQUIRED'):
            bind(plan, {'read_action': [valid[0], []]})

    def test_unsupported_path_constraints_require_review(self):
        cases = (
            ({'type': 'string', 'minLength': 4, 'maxLength': 6, 'pattern': '^[0-9]+$'},
             'OPENAPI_SCHEMA_KEYWORD_UNSUPPORTED'),
            ({'type': 'string', 'format': 'uuid'}, 'OPENAPI_STRING_FORMAT_REVIEW_REQUIRED'),
            ({'type': ['string', 'integer']}, 'OPENAPI_PATH_PARAM_TYPE_UNSUPPORTED'),
            ({'type': 'integer', 'enum': [100, '200']}, 'OPENAPI_INTEGER_ENUM_UNSUPPORTED'),
        )
        for schema, reason in cases:
            with self.subTest(schema=schema):
                spec = spec_30()
                parameter = spec['paths']['/v1/records/{action_id}']['get']['parameters'][0]
                parameter['schema'] = schema
                operation = inspect_openapi(spec, 'study_records')['operations'][0]
                self.assertEqual(operation['status'], 'REVIEW_REQUIRED')
                self.assertIn(reason, operation['reasonCodes'])

    def test_path_draft_without_preserved_schema_requires_reinspection(self):
        plan = inspect_openapi(spec_30(), 'study_records')
        plan['operations'][0].pop('pathTargetSchema', None)
        with self.assertRaisesRegex(Denied, 'OPENAPI_PATH_SCHEMA_REINSPECTION_REQUIRED'):
            bind(plan)

    def test_nullable_const_rejects_null_in_compiled_result(self):
        spec = spec_31()
        spec['components']['schemas']['Session']['properties']['session_id'] = {
            'type': ['string', 'null'], 'const': 'fixed',
        }
        bound = bind(inspect_openapi(spec, 'study_sessions'), {'list_sessions': ['registry']})
        operation = compile_bound_source(bound['sourceDescription']).operations[0]
        operation.result({'ok': True, 'items': [{'session_id': 'fixed', 'active': True}]})
        with self.assertRaisesRegex(Denied, 'DECLARATIVE_LITERAL_INVALID'):
            operation.result({'ok': True, 'items': [{'session_id': None, 'active': True}]})

    def test_nullable_integer_enum_rejects_null_in_compiled_result(self):
        spec = spec_31()
        spec['components']['schemas']['Session']['properties']['session_id'] = {
            'type': ['integer', 'null'], 'enum': [1, 2],
        }
        bound = bind(inspect_openapi(spec, 'study_sessions'), {'list_sessions': ['registry']})
        operation = compile_bound_source(bound['sourceDescription']).operations[0]
        operation.result({'ok': True, 'items': [{'session_id': 1, 'active': True}]})
        with self.assertRaisesRegex(Denied, 'DECLARATIVE_INTEGER_INVALID'):
            operation.result({'ok': True, 'items': [{'session_id': None, 'active': True}]})

    def test_const_with_additional_assertions_requires_review(self):
        spec = spec_31()
        spec['components']['schemas']['Session']['properties']['session_id'] = {
            'type': 'string', 'const': 'fixed', 'minLength': 6,
        }
        operation = inspect_openapi(spec, 'study_sessions')['operations'][0]
        self.assertEqual(operation['status'], 'REVIEW_REQUIRED')
        self.assertIn('OPENAPI_CONST_CONSTRAINTS_REVIEW_REQUIRED', operation['reasonCodes'])

    def test_two_get_methods_same_provider_preserve_independent_targets(self):
        spec=spec_30()
        second=deepcopy(spec['paths']['/v1/records/{action_id}']['get'])
        second['operationId']='read_summary'
        spec['paths']['/v1/records/{action_id}/summary']={'get':second}
        plan=inspect_openapi(spec,'study_records')
        self.assertEqual([row['status'] for row in plan['operations']],
                         ['DRAFT_COMPILABLE','DRAFT_COMPILABLE'])
        bound=bind(plan,targets={'read_action':['3','4'],'read_summary':['3']})
        desc=bound['sourceDescription']
        self.assertEqual({m['name']:m['targets'] for m in desc['methods']},
                         {'read_action':['3','4'],'read_summary':['3']})
        self.assertEqual(len(render_package(desc)),5)

    def test_explicit_selection_reports_every_excluded_method_and_reason(self):
        first_path = '/v1/records/{action_id}'
        second_path = '/v1/records/{action_id}/summary'
        spec = spec_30()
        second = deepcopy(spec['paths'][first_path]['get'])
        second['operationId'] = 'read_summary'
        spec['paths'][second_path] = {'get': second}

        def subset():
            plan = inspect_openapi(spec, 'study_records')
            return bind(plan, selected=['read_action'])

        bound = subset()
        skipped_get = {
            'name': 'read_summary', 'verb': 'GET', 'path': second_path,
            'reason': 'explicitly_not_selected', 'reasonCodes': [],
        }
        with self.subTest(spec='GET only'):
            self.assertEqual(bound['excludedMethods'], ['read_summary'])
            self.assertEqual(bound['excludedMethodDetails'], [skipped_get])
            self.assertEqual([op.name for op in compile_bound_source(
                bound['sourceDescription']).operations], ['read_action'])

        spec['paths'][first_path]['post'] = {
            'operationId': 'write_action', 'responses': {'201': {'description': 'Created'}},
        }
        bound = subset()
        with self.subTest(spec='GET and WRITE'):
            self.assertEqual(bound['excludedMethods'], ['read_summary', 'write_action'])
            self.assertEqual(bound['excludedMethodDetails'], [
                skipped_get,
                {'name': 'write_action', 'verb': 'POST', 'path': first_path,
                 'reason': 'unsupported',
                 'reasonCodes': ['OPENAPI_WRITE_OR_NON_GET_REVIEW_REQUIRED']},
            ])

    def test_valid_json_bytes_and_doc_key_order_same_digest(self):
        spec=spec_30()
        one=inspect_openapi(json.dumps(spec).encode(),'study_records')
        two=inspect_openapi(deepcopy(spec),'study_records')
        self.assertEqual(one['specSha256'],two['specSha256'])
        self.assertEqual(one,two)

    def test_unbounded_or_unknown_http_does_not_create_runnable_methods(self):
        spec=spec_30()
        op=spec['paths']['/v1/records/{action_id}'].pop('get')
        spec['paths']['/v1/records/{action_id}']['trace']=op
        plan=inspect_openapi(spec,'study_records')
        self.assertEqual(plan['operations'][0]['status'],'REVIEW_REQUIRED')
        self.assertEqual(plan['operations'][0]['nextAction'],
                         'REVIEW_WRITE_EFFECT_SEPARATELY')
        self.assertEqual(plan['sourceTemplate']['methods'],[])
        with self.assertRaisesRegex(Denied,'OPENAPI_EXPLICIT_METHOD_SELECTION_REQUIRED'):
            bind_source_draft(plan,'https://trusted.example.invalid',{})

    def test_no_yaml_parser_or_untrusted_origin_inference(self):
        text='openapi: 3.0.3\ninfo:\n  title: Demo\n  version: v1\npaths: {}\n'
        with self.assertRaisesRegex(Denied,'OPENAPI_DOCUMENT_INVALID_JSON'):
            inspect_openapi(text,'study_records')
        plan=inspect_openapi(spec_30(),'study_records')
        with self.assertRaisesRegex(Denied,'SOURCE_ORIGIN_INVALID'):
            bind_source_draft(plan,None,{'read_action':['3']})
        with self.assertRaisesRegex(Denied,'OPENAPI_TARGET_BINDING_REQUIRED'):
            bind_source_draft(plan,'https://trusted.example.invalid',{'read_action':[]})

    def test_path_override_cannot_override_fixed_origin(self):
        spec=spec_30()
        spec['paths']['/v1/records/{action_id}']['servers']=[{
            'url':'http://unsafe.example.invalid'}]
        item=inspect_openapi(spec,'study_records')['operations'][0]
        self.assertEqual(item['status'],'REVIEW_REQUIRED')
        self.assertIn('OPENAPI_OPERATION_SERVER_OVERRIDE_REVIEW_REQUIRED',
                      item['reasonCodes'])

    def test_compiler_rejects_fake_source_plan_with_excessive_targets(self):
        plan=inspect_openapi(spec_30(),'study_records')
        with self.assertRaisesRegex(Denied,'OPENAPI_TARGET_BINDING_REQUIRED'):
            bind_source_draft(plan,'https://trusted.example.invalid',{
                'read_action':['3']*101})

    def test_non_default_path_encoding_is_not_assumed_safe(self):
        for style,explode in (('form',None),('simple',True)):
            spec=spec_30()
            param=spec['paths']['/v1/records/{action_id}']['get']['parameters'][0]
            param['style']=style
            if explode is not None:param['explode']=explode
            row=inspect_openapi(spec,'study_records')['operations'][0]
            self.assertIn('OPENAPI_PATH_ENCODING_UNSUPPORTED',row['reasonCodes'])

    def test_binding_cannot_change_fixed_path_from_proposed_spec(self):
        plan=inspect_openapi(spec_30(),'study_records')
        altered=deepcopy(plan)
        altered['sourceTemplate']['routes'][0]['path']='/v1/admin/{action_id}'
        with self.assertRaisesRegex(Denied,'OPENAPI_DRAFT_INVALID'):
            bind(altered)

    def test_unsupported_method_without_valid_id_remains_visible_as_excluded(self):
        spec=spec_30()
        spec['paths']['/v1/records/{action_id}']['post']={
            'operationId':'invalid-action.name',
            'responses':{'201':{'description':'Created'}}}
        plan=inspect_openapi(spec,'study_records')
        bound=bind(plan,selected=['read_action'])
        self.assertEqual(bound['excludedMethods'],
                         ['POST /v1/records/{action_id}'])
        rejected=[row for row in plan['operations'] if row['name'] is None]
        self.assertEqual(len(rejected),1)
        self.assertEqual(rejected[0]['nextAction'],
                         'REVIEW_WRITE_EFFECT_SEPARATELY')

    def test_forged_draft_cannot_inject_credential_or_unreviewed_method(self):
        plan=inspect_openapi(spec_30(),'study_records')
        bad=deepcopy(plan)
        bad['sourceTemplate']['methods'][0]['credential']='upstream_secret'
        with self.assertRaisesRegex(Denied,'OPENAPI_DRAFT_INVALID'):
            bind(bad)
        bad=deepcopy(plan)
        bad['sourceTemplate']['methods'][0]['targets']=['unexpected']
        with self.assertRaisesRegex(Denied,'OPENAPI_DRAFT_INVALID'):
            bind(bad)
        bad=deepcopy(plan)
        bad['sourceTemplate']['methods'][0]['resultSchema']['fields']['name']['maxLength']=20
        with self.assertRaisesRegex(Denied,'OPENAPI_DRAFT_INVALID'):
            bind(bad)

    def test_reserved_provider_identifier_is_refused_during_intake(self):
        with self.assertRaisesRegex(Denied,'SOURCE_PROVIDER_RESERVED'):
            inspect_openapi(spec_30(),'github')

    def test_complex_schema_combinators_do_not_silently_drop_constraints(self):
        for extra in ({'allOf':[{'type':'string'}]},
                      {'oneOf':[{'type':'string'}]},
                      {'uniqueItems':True}):
            spec=spec_30()
            schema=spec['paths']['/v1/records/{action_id}']['get']['responses']['200']['content']['application/json']['schema']['properties']['name']
            schema.update(extra)
            row=inspect_openapi(spec,'study_records')['operations'][0]
            self.assertIn('OPENAPI_SCHEMA_KEYWORD_UNSUPPORTED',row['reasonCodes'])

    def test_cli_reports_unreviewed_draft_from_local_json_only(self):
        import subprocess,sys
        with TemporaryDirectory(prefix='openapi-cli-test-') as folder:
            file=Path(folder)/'api.json'
            file.write_text(json.dumps(spec_30()),encoding='utf-8')
            run=subprocess.run([sys.executable,'-B','-m',
                'fortis_approvals.extensions.openapi_intake',
                '--spec',str(file),'--provider','study_records'],
                capture_output=True,text=True,timeout=20)
            self.assertEqual(run.returncode,0,run.stderr)
            row=json.loads(run.stdout)
            self.assertEqual(row['status'],'REVIEW_REQUIRED')
            self.assertIsNone(row['sourceTemplate']['origin'])
            self.assertFalse(row['reviewed'])
            self.assertEqual(set(Path(folder).iterdir()),{file})

    def test_cli_refuses_remote_url_without_fetch(self):
        import subprocess,sys
        run=subprocess.run([sys.executable,'-B','-m',
            'fortis_approvals.extensions.openapi_intake',
            '--spec','https://example.invalid/openapi.json',
            '--provider','study_records'],
            capture_output=True,text=True,timeout=20)
        self.assertEqual(run.returncode,2)
        self.assertIn('OPENAPI_LOCAL_SPEC_REQUIRED',run.stderr)

    def test_malformed_openapi_object_shapes_fail_closed_without_tracebacks(self):
        # Broad input grammar regression: malformed third-party documents must
        # never escape as an AttributeError/TypeError/KeyError from the intake.
        editors=(
          ('info',lambda d,v:d.__setitem__('info',v)),
          ('paths',lambda d,v:d.__setitem__('paths',v)),
          ('path_item',lambda d,v:d['paths'].__setitem__(
              '/v1/records/{action_id}',v)),
          ('operation',lambda d,v:d['paths']['/v1/records/{action_id}']
              .__setitem__('get',v)),
          ('parameters',lambda d,v:d['paths']['/v1/records/{action_id}']['get']
              .__setitem__('parameters',v)),
          ('responses',lambda d,v:d['paths']['/v1/records/{action_id}']['get']
              .__setitem__('responses',v)),
          ('200_response',lambda d,v:d['paths']['/v1/records/{action_id}']['get']
              ['responses'].__setitem__('200',v)),
          ('content',lambda d,v:d['paths']['/v1/records/{action_id}']['get']
              ['responses']['200'].__setitem__('content',v)),
          ('schema',lambda d,v:d['paths']['/v1/records/{action_id}']['get']
              ['responses']['200']['content']['application/json']
              .__setitem__('schema',v)),
          ('properties',lambda d,v:d['paths']['/v1/records/{action_id}']['get']
              ['responses']['200']['content']['application/json']['schema']
              .__setitem__('properties',v)))
        cases=(None,[],{},False,42,'x',{'type':'object'})
        for value in cases:
            for name,edit in editors:
                with self.subTest(name=name,value=value):
                    spec=spec_30();edit(spec,value)
                    try:inspect_openapi(spec,'study_records')
                    except Denied:continue
                    # A returned plan is still unreviewed, never runtime ready.
                    else:
                        plan=inspect_openapi(spec,'study_records')
                        self.assertFalse(plan['reviewed'])
                        self.assertEqual(plan['status'],'REVIEW_REQUIRED')

    def test_duplicate_operation_id_and_invalid_selection_rejected(self):
        spec=spec_30()
        spec['paths']['/v1/records/{action_id}']['post']={
            'operationId':'read_action','responses':{}}
        with self.assertRaisesRegex(Denied,'OPENAPI_DUPLICATE_OPERATION_ID'):
            inspect_openapi(spec,'study_records')
        plan=inspect_openapi(spec_30(),'study_records')
        with self.assertRaisesRegex(Denied,'OPENAPI_TARGET_BINDING_REQUIRED'):
            bind(plan,targets={'unknown':['1']})
        with self.assertRaisesRegex(Denied,'INTEGRATION_ORIGIN_INVALID'):
            bind(plan,origin='http://unsafe.invalid')

if __name__=='__main__':unittest.main(verbosity=2)
