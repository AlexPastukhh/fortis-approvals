"""Real-contract parity for source-owned read schemas. No Gateway installation."""
from copy import deepcopy
import unittest

from fortis_approvals.core import Denied
from fortis_approvals.extensions.declarative_read import compile_read_provider
from fortis_approvals.extensions.http import Route, JSONAPI
from fortis_approvals.extensions.runtime import ExtensionConfig, ExtensionRuntime
from fortis_approvals.integrations.action_core.extension import (
    PROVIDER as ACTION, read_action)
from fortis_approvals.integrations.observatory.extension import (
    PROVIDER as OBS, _read_health, _list_sessions)


def S(maxlen,fmt=None,printable=False,minlen=1):
    return {'type':'string','minLength':minlen,'maxLength':maxlen,'unit':'codepoints',
            'printable':printable,'format':fmt}

def I(minimum=None,maximum=None,choices=None):
    return {'type':'integer','minimum':minimum,'maximum':maximum,'choices':choices}

def B(value=None):return {'type':'boolean','equals':value}
def L(value):return {'type':'literal','equals':value}
def O(fields):return {'type':'object','fields':fields}
def A(max_items,items):return {'type':'array','maxItems':max_items,'items':items}
def N(item):return {'type':'nullable','item':item}

NONE={'targetEquals':None,'unique':None,'page':None}
ACTION_SPEC={
    'name':'read_action','description':'Read current Action definition',
    'version':'1','route':'read_action','credential':'read',
    'targets':['3','4'],'paramsSchema':O({}),'pathTargetParam':'action_id','query':{},
    'resultSchema':O({
        'action_id':I(1,choices=[3,4]),'name':S(200,printable=True),
        'category':S(80,{'kind':'lowerSlug'}),
        'current_version_number':I(1),
        'definition_yaml':S(65536), 'schedule_active':B(),
    }),
    'projection':None,'checks':{
        **NONE,'targetEquals':{'field':'action_id','coerce':'decimal'}},
    'maxResultBytes':65536,
}
HEALTH_SPEC={
    'name':'health','description':'Read health', 'version':'1',
    'route':'health','credential':'api','targets':['service'],
    'paramsSchema':O({}),'pathTargetParam':None,'query':{},
    'resultSchema':O({'ok':B(True),'service':L('fortis-observatory-api'),
                      'mode':L('staging_only')}),
    'projection':{'ok':'ok','service':'service','mode':'mode'},
    'checks':NONE,'maxResultBytes':65536,
}
SESSIONS_SPEC={
    'name':'list_sessions','description':'Read authorized session identifiers',
    'version':'1','route':'sessions','credential':'api','targets':['registry'],
    'paramsSchema':O({}),'pathTargetParam':None,'query':{},
    'resultSchema':O({
        'ok':B(True),
        'sessions':A(200,O({
            'conversation_id':S(100,{'kind':'alnumDash'},minlen=8),
            'session_id':N(S(35,{'kind':'prefixLowerHex','prefix':'rs_','digits':32}))
        }))}),
    'projection':{'ok':'ok','sessions':{'array':'sessions',
        'fields':{'conversation_id':'conversation_id',
                  'session_id':'reporting_session_id'}}},
    'checks':{**NONE,'unique':{'array':'sessions','field':'conversation_id'}},
    'maxResultBytes':65536,
}

def compiled_providers():
    return (compile_read_provider('action_core', ACTION.api,(ACTION_SPEC,)),
            compile_read_provider('observatory',OBS.api,(HEALTH_SPEC,SESSIONS_SPEC)))

class Ctx:
    def __init__(self,target,response):
        self.target=target;self.params={};self.response=response;self.calls=[]
    def call(self,route,**kwargs):
        self.calls.append((route,kwargs))
        return deepcopy(self.response)

def action_sample(action_id=3):
    return {'action_id':action_id,'name':'Research', 'category':'research',
            'current_version_number':3,
            'definition_yaml':'name: Research\ninstruction: Read only\n',
            'schedule_active':False}

def valid_sessions():
    return {'ok':True,'sessions':[{'conversation_id':'12345678-1234-1234-1234-123456789abc',
                                  'reporting_session_id':'rs_'+'a'*32,
                                  'title':'private title','messages':['secret']}]}

def parity(callable_a,callable_b,response,target):
    ca=Ctx(target,deepcopy(response));cb=Ctx(target,deepcopy(response))
    errors=[];values=[]
    for fn,c in ((callable_a,ca),(callable_b,cb)):
        try:values.append(fn(c));errors.append(None)
        except Denied as exc:values.append(None);errors.append(str(exc))
    return values,errors,ca.calls,cb.calls

class RealProviderComparison(unittest.TestCase):
    def setUp(self):
        self.a,self.b=compiled_providers()
    def act(self):return self.a.operations[0]
    def health(self):return self.b.operations[0]
    def sessions(self):return self.b.operations[1]
    def test_preserves_operation_names_credentials_and_routes(self):
        self.assertEqual([(o.name,o.credential,o.routes) for o in self.a.operations],
                         [(o.name,o.credential,o.routes) for o in ACTION.operations])
        self.assertEqual([(o.name,o.credential,o.routes) for o in self.b.operations],
                         [(o.name,o.credential,o.routes) for o in OBS.operations])
        self.assertIs(self.a.api,ACTION.api)
        self.assertIs(self.b.api,OBS.api)
    def test_action_valid_contract_and_route(self):
        for target in ('3','4'):
            response=action_sample(int(target))
            v,e,c,d=parity(read_action,self.act().execute,response,target)
            self.assertEqual(e,[None,None]);self.assertEqual(v[0],v[1])
            self.assertEqual(c,[('read_action',{'path':{'action_id':target}})])
            self.assertEqual(c,d)
    def test_action_target_denied_before_call(self):
        for target in ('2','5','03','../3','3/4','',3,None):
            v,e,c,d=parity(read_action,self.act().execute,action_sample(),target)
            self.assertTrue(all(e));self.assertEqual(c,[]);self.assertEqual(d,[])
    def test_action_wrong_id_denied(self):
        _,e,_,_=parity(read_action,self.act().execute,action_sample(4),'3')
        self.assertTrue(all(e))
    def test_action_wrong_result_fields_and_types_denied(self):
        variants=[]
        for key,val in [('action_id',True),('current_version_number',True),
                        ('schedule_active',1),('category','Research'),('name',''),
                        ('definition_yaml',''),('action_id',5)]:
            d=action_sample();d[key]=val;variants.append(d)
        d=action_sample();d['secret']='secret';variants.append(d)
        d=action_sample();del d['schedule_active'];variants.append(d)
        for d in variants:
            with self.subTest(d=d):
                _,e,_,_=parity(read_action,self.act().execute,d,'3')
                self.assertTrue(all(e))
    def test_action_name_control_chars_denied(self):
        d=action_sample();d['name']='Internal\x00Secret'
        _,e,_,_=parity(read_action,self.act().execute,d,'3')
        self.assertTrue(all(e),f"Control char parity gap: {e}")
    def test_action_name_200_codepoints_not_200_bytes(self):
        # Existing Action Core uses len(text), not len(UTF-8 bytes).
        d=action_sample();d['name']='ю'*101
        v,e,_,_=parity(read_action,self.act().execute,d,'3')
        self.assertEqual(e,[None,None]);self.assertEqual(v[0],v[1])
        d['name']='ю'*201
        _,e,_,_=parity(read_action,self.act().execute,d,'3')
        self.assertTrue(all(e))
    def test_action_category_hyphen_valid(self):
        d=action_sample();d['category']='research_group-1'
        v,e,_,_=parity(read_action,self.act().execute,d,'3')
        self.assertEqual(e,[None,None]);self.assertEqual(v[0],v[1])

    def test_action_yaml_newline_and_nontrivial_length(self):
        d=action_sample();d['definition_yaml']='\n'+'x'*4000
        v,e,_,_=parity(read_action,self.act().execute,d,'3')
        self.assertEqual(e,[None,None]);self.assertEqual(v[0],v[1])
    def test_action_overall_result_bound(self):
        d=action_sample();d['definition_yaml']='x'*65536
        _,e,_,_=parity(read_action,self.act().execute,d,'3')
        self.assertTrue(all(e))
    def test_observatory_health_safe_projection(self):
        d={'ok':True,'service':'fortis-observatory-api','mode':'staging_only','debugToken':'secret'}
        v,e,c,d2=parity(_read_health,self.health().execute,d,'service')
        self.assertEqual(e,[None,None]);self.assertEqual(v[0],v[1])
        self.assertEqual(set(v[0]),{'ok','service','mode'})
        self.assertEqual(c,[('health',{})]);self.assertEqual(c,d2)
    def test_observatory_health_literal_error(self):
        for change in ({'ok':False},{'mode':'production'},{'service':'unexpected'}):
            d={'ok':True,'service':'fortis-observatory-api','mode':'staging_only'}
            d.update(change)
            _,e,_,_=parity(_read_health,self.health().execute,d,'service')
            self.assertTrue(all(e))
    def test_observatory_health_denies_wrong_target(self):
        _,e,c,d=parity(_read_health,self.health().execute,
               {'ok':True,'service':'fortis-observatory-api','mode':'staging_only'},'registry')
        self.assertTrue(all(e));self.assertEqual((c,d),([],[]))
    def test_observatory_sessions_rename_and_no_leak(self):
        raw=valid_sessions()
        v,e,c,d=parity(_list_sessions,self.sessions().execute,raw,'registry')
        self.assertEqual(e,[None,None]);self.assertEqual(v[0],v[1])
        self.assertEqual(set(v[0]['sessions'][0]),{'conversation_id','session_id'})
        self.assertEqual((c,d),([('sessions',{})],[('sessions',{})]))
    def test_observatory_sessions_duplicate_id(self):
        d=valid_sessions();d['sessions'].append(deepcopy(d['sessions'][0]))
        _,e,_,_=parity(_list_sessions,self.sessions().execute,d,'registry')
        self.assertTrue(all(e))
    def test_observatory_sessions_null_session_id(self):
        d=valid_sessions();d['sessions'][0]['reporting_session_id']=None
        v,e,_,_=parity(_list_sessions,self.sessions().execute,d,'registry')
        self.assertEqual(e,[None,None]);self.assertEqual(v[0],v[1])
    def test_observatory_sessions_missing_identifier(self):
        d=valid_sessions();del d['sessions'][0]['conversation_id']
        _,e,_,_=parity(_list_sessions,self.sessions().execute,d,'registry')
        self.assertTrue(all(e))
    def test_observatory_sessions_bad_format(self):
        for key,val in [('conversation_id','!'),('reporting_session_id','rs_BAD')]:
            d=valid_sessions();d['sessions'][0][key]=val
            _,e,_,_=parity(_list_sessions,self.sessions().execute,d,'registry')
            self.assertTrue(all(e))
    def test_observatory_sessions_accepts_200_entries(self):
        d={'ok':True,'sessions':[{'conversation_id':f'chat-{i:04d}',
             'reporting_session_id':None} for i in range(200)]}
        v,e,_,_=parity(_list_sessions,self.sessions().execute,d,'registry')
        self.assertEqual(e,[None,None]);self.assertEqual(v[0],v[1]);self.assertEqual(len(v[0]['sessions']),200)
    def test_observatory_sessions_rejects_201_entries(self):
        d={'ok':True,'sessions':[{'conversation_id':f'chat-{i:04d}',
             'reporting_session_id':None} for i in range(201)]}
        _,e,_,_=parity(_list_sessions,self.sessions().execute,d,'registry')
        self.assertTrue(all(e))
    def test_observatory_sessions_wrong_target(self):
        _,e,c,d=parity(_list_sessions,self.sessions().execute,valid_sessions(),'service')
        self.assertTrue(all(e));self.assertEqual((c,d),([],[]))
    def test_known_trusted_formats_cannot_be_overridden_from_descriptor(self):
        bad=deepcopy(ACTION_SPEC)
        bad['resultSchema']['fields']['category']['format']={'kind':'arbitrary_regex'}
        with self.assertRaisesRegex(Denied,'DECLARATIVE_FORMAT_UNSUPPORTED'):
            compile_read_provider('action_core',ACTION.api,(bad,))
    def test_source_scoped_config_without_new_gateway_runtime(self):
        class Vault:
            def readiness(self,alias):
                return {'configured':True,'ready':True,'status':'READY'}
        cfg=ExtensionConfig({'schemaVersion':1,'providers':{
         'action_core':{'credentials':{'read':'action-core-read'},
           'operations':{'read_action':{'policy':'ALLOW','targets':['3','4']}}},
         'observatory':{'credentials':{'api':'observatory-api'},
           'operations':{'health':{'policy':'ASK','targets':['service']},
                         'list_sessions':{'policy':'DENY','targets':['registry']}}}}})
        rt=ExtensionRuntime(cfg,providers=(self.a,self.b),actors=('actor',),
                            default_actor='actor',vault=Vault())
        ops=rt.catalog_for('actor')['operations']
        self.assertEqual(len(ops),4)
        self.assertEqual([x['policy'] for x in ops if x['service']=='observatory'],
                         ['ASK','DENY'])
class CompilerBoundaries(unittest.TestCase):
    def test_unreviewed_route_is_not_imported(self):
        bad=deepcopy(ACTION_SPEC);bad['route']='unregistered'
        with self.assertRaisesRegex(Denied,'DECLARATIVE_ROUTE_NOT_REGISTERED'):
            compile_read_provider('action_core',ACTION.api,(bad,))

    def test_write_definition_cannot_be_smuggled_through_read_compiler(self):
        bad=deepcopy(ACTION_SPEC);bad['kind']='write'
        with self.assertRaisesRegex(Denied,'DECLARATIVE_DEFINITION_INVALID'):
            compile_read_provider('action_core',ACTION.api,(bad,))

    def test_duplicate_method_name_rejected(self):
        with self.assertRaisesRegex(Denied,'DECLARATIVE_DUPLICATE_METHOD'):
            compile_read_provider('action_core',ACTION.api,(ACTION_SPEC,ACTION_SPEC))

    def test_caller_credentials_denied_at_compile(self):
        bad=deepcopy(ACTION_SPEC)
        bad['paramsSchema']=O({'apiKey':S(200)})
        with self.assertRaisesRegex(Denied,'DECLARATIVE_CREDENTIAL_PARAM_DENIED'):
            compile_read_provider('action_core',ACTION.api,(bad,))

    def test_manual_hook_rejects_only_matching_operation(self):
        def reviewed_only(value):
            if value['name'] != 'Reviewed':
                raise Denied('MANUAL_BUSINESS_CONSTRAINT')
        provider=compile_read_provider('action_core',ACTION.api,(ACTION_SPEC,),
                                       postchecks={'read_action':reviewed_only})
        ctx=Ctx('3',action_sample())
        with self.assertRaisesRegex(Denied,'MANUAL_BUSINESS_CONSTRAINT'):
            provider.operations[0].execute(ctx)
        accepted=action_sample();accepted['name']='Reviewed'
        self.assertEqual(provider.operations[0].execute(Ctx('3',accepted)),accepted)

    def test_manual_hook_mutation_forbidden(self):
        def mutate(value):
            value['name']='different'
        provider=compile_read_provider('action_core',ACTION.api,(ACTION_SPEC,),
                                       postchecks={'read_action':mutate})
        with self.assertRaisesRegex(Denied,'DECLARATIVE_HOOK_MUTATED_RESULT'):
            provider.operations[0].execute(Ctx('3',action_sample()))

    def test_execution_context_check_is_separate_from_result_hook(self):
        def check_target(target,params,value):
            if target!='4':raise Denied('CUSTOM_CONTEXT_REJECT')
        provider=compile_read_provider('action_core',ACTION.api,(ACTION_SPEC,),
            context_checks={'read_action':check_target})
        # A context hook cannot be re-run by result(value) without a request.
        provider.operations[0].result(action_sample())
        with self.assertRaisesRegex(Denied,'CUSTOM_CONTEXT_REJECT'):
            provider.operations[0].execute(Ctx('3',action_sample()))
        good=action_sample(4)
        self.assertEqual(provider.operations[0].execute(Ctx('4',good)),good)

    def test_hook_disappearing_after_method_rename_is_error(self):
        bad=deepcopy(ACTION_SPEC);bad['name']='new_action_read'
        with self.assertRaisesRegex(Denied,'DECLARATIVE_HOOK_METHOD_MISSING'):
            compile_read_provider('action_core',ACTION.api,(bad,),
                                  postchecks={'read_action':lambda *_:None})

    def test_read_rejects_non_get_route_even_if_whitelisted(self):
        transport=JSONAPI('https://data.example.invalid',(
            Route('write','POST','/v1/item',readonly=False),))
        bad=deepcopy(HEALTH_SPEC);bad['route']='write'
        with self.assertRaisesRegex(Denied,'DECLARATIVE_READ_ONLY_REQUIRED'):
            compile_read_provider('research_only',transport,(bad,))

    def test_decimal_target_coercion_rejects_invalid_descriptor(self):
        bad=deepcopy(ACTION_SPEC)
        bad['targets']=['registry']
        bad['resultSchema']['fields']['action_id']['choices']=None
        with self.assertRaisesRegex(Denied,'DECLARATIVE_DECIMAL_TARGET_INVALID'):
            compile_read_provider('action_core',ACTION.api,(bad,))

    def test_decimal_target_coercion_rejects_ambiguous_leading_zero(self):
        bad=deepcopy(ACTION_SPEC)
        bad['targets']=['03']
        bad['resultSchema']['fields']['action_id']['choices']=None
        with self.assertRaisesRegex(Denied,'DECLARATIVE_DECIMAL_TARGET_INVALID'):
            compile_read_provider('action_core',ACTION.api,(bad,))

    def test_unhashable_nested_unique_field_rejected_during_compile(self):
        api=JSONAPI('https://data.example.invalid',(
            Route('list','GET','/v1/list',readonly=True),))
        bad=deepcopy(HEALTH_SPEC)
        bad['name']='list'
        bad['route']='list'
        bad['resultSchema']=O({'items':A(4,O({'key':O({'value':S(20)})}))})
        bad['projection']=None
        bad['checks']={**NONE,'unique':{'array':'items','field':'key'}}
        with self.assertRaisesRegex(Denied,'DECLARATIVE_UNIQUE_KEY_UNSUPPORTED'):
            compile_read_provider('inventory',api,(bad,))

    def test_result_only_manual_hook_rechecked_by_result_validator(self):
        def reviewed_only(value):
            if value['name']!='Reviewed':raise Denied('MANUAL_BUSINESS_CONSTRAINT')
        provider=compile_read_provider('action_core',ACTION.api,(ACTION_SPEC,),
                                       postchecks={'read_action':reviewed_only})
        with self.assertRaisesRegex(Denied,'MANUAL_BUSINESS_CONSTRAINT'):
            provider.operations[0].result(action_sample())
        with self.assertRaisesRegex(Denied,'MANUAL_BUSINESS_CONSTRAINT'):
            provider.operations[0].execute(Ctx('3',action_sample()))
        good=action_sample();good['name']='Reviewed'
        provider.operations[0].result(good)

    def test_wrong_configured_target_rejected_before_catalog(self):
        class Vault:
            def readiness(self,alias):return dict(configured=True,ready=True,status='READY')
        provider=compile_read_provider('action_core',ACTION.api,(ACTION_SPEC,))
        bad=ExtensionConfig({'schemaVersion':1,'providers':{
         'action_core':{'credentials':{'read':'audit-only'},'operations':{
            'read_action':{'policy':'ALLOW','targets':['5']}}}}})
        with self.assertRaisesRegex(Denied,'INTEGRATION_TARGET_OUTSIDE_DEFINITION'):
            ExtensionRuntime(bad,providers=(provider,),actors=('actor',),
                             default_actor='actor',vault=Vault())

    def test_manual_operation_unrestricted_targets_legacy_compatible(self):
        from dataclasses import replace
        generic=compile_read_provider('observatory',OBS.api,(HEALTH_SPEC,))
        mixed=replace(generic,operations=generic.operations+(OBS.operations[1],))
        self.assertEqual(generic.operations[0].allowed_targets,('service',))
        self.assertEqual(OBS.operations[1].allowed_targets,())
        cfg=ExtensionConfig({'schemaVersion':1,'providers':{
          'observatory':{'credentials':{'api':'audit-only'},'operations':{
            'health':{'policy':'ALLOW','targets':['service']},
            'list_sessions':{'policy':'ASK','targets':['registry']}}}}})
        self.assertEqual(len(ExtensionRuntime(cfg,providers=(mixed,),actors=('actor',),
             default_actor='actor').rules),2)

    def test_compile_refuses_missing_object_fields_with_denial(self):
        bad=deepcopy(HEALTH_SPEC)
        bad['paramsSchema']={'type':'object'}
        with self.assertRaisesRegex(Denied,'DECLARATIVE_DEFINITION_INVALID'):
            compile_read_provider('observatory',OBS.api,(bad,))

    def test_compile_refuses_non_integer_page_offset_and_limit(self):
        transport=JSONAPI('https://data.example.invalid',(
            Route('listing','GET','/v1/items',readonly=True,
                  query_keys=('offset','limit','revision')),))
        spec=deepcopy(HEALTH_SPEC)
        spec.update(name='listing',route='listing',targets=['registry'],
             paramsSchema=O({'offset':S(12),'limit':S(12),'revision':N(S(32))}),
             query={'offset':'offset','limit':'limit','revision':'revision'},
             resultSchema=O({'items':A(25,O({'id':S(20)})),
                             'nextOffset':N(I(0,100)),'revision':S(32)}),
             projection=None,
             checks={'targetEquals':None,'unique':None,
                     'page':{'items':'items','nextOffset':'nextOffset','revision':'revision',
                     'offsetParam':'offset','limitParam':'limit','revisionParam':'revision'}})
        with self.assertRaisesRegex(Denied,'DECLARATIVE_PAGE_TYPES_INVALID'):
            compile_read_provider('inventory',transport,(spec,))
        spec['paramsSchema']['fields']['offset']=I(0,100)
        spec['paramsSchema']['fields']['limit']=I(1,25)
        compile_read_provider('inventory',transport,(spec,))
        spec['resultSchema']['fields']['nextOffset']=S(20)
        with self.assertRaisesRegex(Denied,'DECLARATIVE_PAGE_TYPES_INVALID'):
            compile_read_provider('inventory',transport,(spec,))

    def test_unique_field_rechecked_by_result_validator(self):
        spec=deepcopy(SESSIONS_SPEC)
        provider=compile_read_provider('observatory',OBS.api,(spec,))
        value={'ok':True,'sessions':[
           {'conversation_id':'a'*8,'session_id':None},
           {'conversation_id':'a'*8,'session_id':None}]}
        with self.assertRaisesRegex(Denied,'DECLARATIVE_DUPLICATE_ROW'):
            provider.operations[0].result(value)

    def test_query_paging_no_code_for_method(self):
        transport=JSONAPI('https://data.example.invalid',(
            Route('listing','GET','/v1/items',readonly=True,
                  query_keys=('offset','limit','revision')),))
        page_spec={'name':'listing','description':'Page through fixed inventory',
            'version':'1','route':'listing','credential':None,'targets':['registry'],
            'paramsSchema':O({'offset':I(0,1000),'limit':I(1,100),
                              'revision':N(S(64))}),
            'pathTargetParam':None,
            'query':{'offset':'offset','limit':'limit','revision':'revision'},
            'resultSchema':O({'items':A(100,O({'id':S(20)})),
                              'nextOffset':N(I(0,1000)), 'revision':S(64)}),
            'projection':None,
            'checks':{'targetEquals':None,'unique':{'array':'items','field':'id'},
               'page':{'items':'items','nextOffset':'nextOffset','revision':'revision',
                       'offsetParam':'offset','limitParam':'limit',
                       'revisionParam':'revision'}}, 'maxResultBytes':65536}
        provider=compile_read_provider('inventory',transport,(page_spec,))
        op=provider.operations[0]
        response={'items':[{'id':'item01'},{'id':'item02'}],
                  'nextOffset':2,'revision':'rev1'}
        ctx=Ctx('registry',response)
        ctx.params={'offset':0,'limit':2,'revision':None}
        self.assertEqual(op.execute(ctx),response)
        self.assertEqual(ctx.calls,[('listing',{'query':{'offset':0,'limit':2}})])
        ctx.params={'offset':2,'limit':2,'revision':None};ctx.calls=[]
        with self.assertRaisesRegex(Denied,'DECLARATIVE_REVISION_REQUIRED'):
            op.execute(ctx)
        self.assertEqual(ctx.calls,[])
        ctx.params={'offset':2,'limit':2,'revision':'wrong'}
        with self.assertRaisesRegex(Denied,'DECLARATIVE_PAGE_MISMATCH'):
            op.execute(ctx)
        ctx.params={'offset':0,'limit':2,'revision':None}
        ctx.response['nextOffset']=99
        with self.assertRaisesRegex(Denied,'DECLARATIVE_NEXT_OFFSET_MISMATCH'):
            op.execute(ctx)
        ctx.response['nextOffset']=2
        ctx.response['items'][1]['id']='item01'
        with self.assertRaisesRegex(Denied,'DECLARATIVE_DUPLICATE_ROW'):
            op.execute(ctx)


if __name__=='__main__':unittest.main(verbosity=2)
