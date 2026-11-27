'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const path=require('node:path');

const full=fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8');
const html=fs.readFileSync(path.join(__dirname,'../static/index.html'),'utf8');
const start=full.indexOf('// Separate, opt-in local restriction UI.');
const end=full.indexOf('function displayProviderInventory(){',start);
assert.ok(start>=0&&end>start);
const source=full.slice(start,end);
const uuid='38e27390-348b-4a01-b06b-7e56cf9daba8';
const prefix='/v1/owner/policy/local-deny';
const version='test|owner-local-deny:0';

function harness(){
 const elements=new Map(),calls=[];
 const state={
  inventory:{localDenyOnly:true,localPolicyRevision:0,policyVersion:version},
  cap:{configured:true,kind:'OWNER_LOCAL_EXACT_DENY_ONLY',ownerOnly:true,
   requiresFreshStrongWebAuthn:true,canGrantAllow:false,canRemoveDenial:false},
  credentialCalls:0,beginChange:x=>x,finishError:false,found:true,credentialError:false,
  duringCredential:null
 };
 const row={provider:'sonarcloud',providerType:'native',operation:'accept_issue',
  scope:'actor',actor:'agent-1',target:null,active:true,configured:true,
  configuredPolicy:'ASK',effectivePolicy:'UNKNOWN',localDenialApplied:false,localDenyEditable:true};
 const $=id=>{
  if(!elements.has(id))elements.set(id,{value:'',hidden:true,disabled:true,
    textContent:'',addEventListener(type,callback){this[type]=callback;}});
  return elements.get(id);
 };
 const api=async(url,body,secured)=>{
  const call={url,body:body?JSON.parse(JSON.stringify(body)):undefined,secured};
  calls.push(call);
  if(url===prefix+'/capabilities'){
   if(state.cap===null)throw Error('NOT_FOUND');
   return state.cap;
  }
  assert.equal(secured,true);
  if(url===prefix+'/begin'){
   return {kind:'OWNER_LOCAL_DENY_APPLY_CEREMONY',runtimeIntegrated:false,
    newPolicy:'DENY',ceremonyId:'synthetic-ceremony',changeDigest:'a'.repeat(64),
    options:{publicKey:{userVerification:'required'}},
    change:state.beginChange({...call.body.candidate,newPolicy:'DENY',
     purpose:'OWNER_LOCAL_EXACT_DENY_APPLY_V1',requestId:uuid,expiresAt:2000,
     sourceDigest:'b'.repeat(64),credentialGenerationDigest:'c'.repeat(64)})};
  }
  if(url===prefix+'/finish'){
   if(state.finishError)throw Error('RESPONSE_LOST');
   assert.equal(call.body.change.requestId,uuid);
   return {kind:'OWNER_LOCAL_DENY_ONLY_COMMIT',requestId:uuid,
    localDenyCommitted:true,runtimeIntegrated:false,canGrantAllow:false,
    oldPolicy:'ASK',newPolicy:'DENY',appliedRevision:1,currentRevision:1};
  }
  if(url===prefix+'/readback')return {requestId:uuid,found:state.found,
   appliedRevision:state.found?1:null,currentRevision:state.found?1:0,
   runtimeIntegrated:false};
  throw Error('UNEXPECTED_URL '+url);
 };
 const ctx=vm.createContext({$,api,action:fn=>fn,
  displayProviderInventory(){},row,
  ceremony:async()=>{state.credentialCalls++;
   if(state.duringCredential)state.duringCredential();
   if(state.credentialError)throw Error('CANCELLED');
   return {syntheticOnly:true};
  },
  initialInventory:state.inventory});
 const run=code=>vm.runInContext(code,ctx);
 run("let csrf='session-csrf',tab='providers',providerInventory=initialInventory,policyReviewBusy=false;\n"+source);
 const load=async()=>{run('resetLocalDenyPanel()');await run('loadLocalDenyCapabilities(csrf,localDenyEpoch)');};
 const pick=async()=>{await load();run('selectLocalDeny(row)');$('local-deny-target').value='ISSUE-1';$('local-deny-target').input();};
 const prepare=()=>run('prepareLocalDeny()');
 const confirm=()=>run('confirmLocalDeny()');
 const readback=()=>run('readbackLocalDeny()');
 return {state,calls,$,run,load,pick,prepare,confirm,readback,row};
}

test('markup hidden and disabled; missing capability or normal inventory cannot enable',async()=>{
 assert.match(html,/id="local-deny-panel" hidden/);
 assert.match(html,/id="local-deny-confirm" type="button" disabled/);
 for(const cap of [null,{configured:false},{configured:true}]){
  const h=harness();h.state.cap=cap;await h.load();
  assert.equal(h.$('local-deny-panel').hidden,true);
  assert.equal(h.$('local-deny-prepare').disabled,true);
  await h.prepare();await h.confirm();
  assert.equal(h.calls.filter(c=>c.body).length,0);
 }
 const h=harness();h.state.inventory.localDenyOnly=false;await h.load();
 assert.equal(h.$('local-deny-panel').hidden,true);
});

test('actor-source target prepare produces no effect before separate fresh confirmation',async()=>{
 const h=harness();await h.pick();await h.prepare();
 assert.equal(h.state.credentialCalls,0);
 assert.equal(h.calls.filter(c=>c.url===prefix+'/finish').length,0);
 const candidate=h.calls.find(c=>c.url===prefix+'/begin').body.candidate;
 assert.equal(candidate.target,'ISSUE-1');
 assert.equal(candidate.expectedConfiguredScope,'actor');
 assert.equal(candidate.expectedRevision,0);
 assert.equal(candidate.expectedPolicyVersion,version);
 assert.match(h.$('local-deny-result').textContent,/ASK → DENY/);
 assert.equal(h.$('local-deny-confirm').disabled,false);
 await h.confirm();assert.equal(h.state.credentialCalls,1);
 assert.equal(h.calls.filter(c=>c.url===prefix+'/finish').length,1);
 assert.equal(h.$('local-deny-confirm').disabled,true);
 assert.match(h.$('local-deny-result').textContent,/Локальная запись DENY подтверждена/);
 await h.confirm();assert.equal(h.calls.filter(c=>c.url===prefix+'/finish').length,1);
});

test('exact configured rule cannot substitute target or use actor fallback',async()=>{
 const h=harness();h.run("row.scope='exact';row.target='ISSUE-1';row.effectivePolicy='ASK'");
 await h.load();h.run('selectLocalDeny(row)');
 assert.equal(h.$('local-deny-target').disabled,true);
 h.$('local-deny-target').value='ISSUE-2';await h.prepare();
 assert.equal(h.calls.filter(c=>c.url===prefix+'/begin').length,0);
 h.$('local-deny-target').value='ISSUE-1';await h.prepare();
 const c=h.calls.find(x=>x.url===prefix+'/begin').body.candidate;
 assert.equal('expectedConfiguredScope' in c,false);
});

test('wrong descriptor target or newPolicy cannot reach WebAuthn',async()=>{
 for(const patch of [{target:'ISSUE-2'},{newPolicy:'ALLOW'},{expectedRevision:5}]){
  const h=harness();await h.pick();
  h.state.beginChange=change=>({...change,...patch});
  await assert.rejects(h.prepare());
  await h.confirm();
  assert.equal(h.state.credentialCalls,0);
  assert.equal(h.calls.filter(c=>c.url===prefix+'/finish').length,0);
 }
});

test('changed target or tab/session invalidates prepared challenge',async()=>{
 const h=harness();await h.pick();await h.prepare();
 h.$('local-deny-target').value='ISSUE-2';h.$('local-deny-target').input();
 await h.confirm();assert.equal(h.state.credentialCalls,0);
 await h.prepare();
 h.state.duringCredential=()=>h.run("csrf=null;resetLocalDenyPanel()");
 await h.confirm();
 assert.equal(h.state.credentialCalls,1);
 assert.equal(h.calls.filter(c=>c.url===prefix+'/finish').length,0);
});

test('cancelled WebAuthn never sends finish',async()=>{
 const h=harness();await h.pick();await h.prepare();h.state.credentialError=true;
 await assert.rejects(h.confirm());
 assert.equal(h.calls.filter(c=>c.url===prefix+'/finish').length,0);
 assert.equal(h.$('local-deny-readback').disabled,true);
});

test('lost finish response holds further actions; readback alone never retries',async()=>{
 const h=harness();await h.pick();await h.prepare();h.state.finishError=true;
 await assert.rejects(h.confirm());
 assert.match(h.$('local-deny-result').textContent,new RegExp(uuid));
 assert.equal(h.$('local-deny-readback').disabled,false);
 await h.confirm();await h.prepare();
 assert.equal(h.calls.filter(c=>c.url===prefix+'/finish').length,1);
 h.state.found=false;await h.readback();
 assert.match(h.$('local-deny-result').textContent,/не доказывает отсутствие эффекта/);
 assert.equal(h.$('local-deny-prepare').disabled,true);
 h.state.found=true;await h.readback();
 assert.equal(h.calls.filter(c=>c.url===prefix+'/finish').length,1);
 assert.equal(h.calls.filter(c=>c.url===prefix+'/readback').length,2);
 assert.equal(h.$('local-deny-readback').disabled,true);
});

test('global, extension, nonliteral, inactive or previously denied rows are not selectable',async()=>{
 const h=harness();await h.load();
 for(const patch of [
  {scope:'global'},{providerType:'extension'},{configuredPolicy:'CONDITIONAL'},
  {active:false},{configuredPolicy:'DENY'},{localDenialApplied:true},{localDenyEditable:false}
 ]){
  Object.assign(h.row,patch);
  assert.equal(h.run('canSelectLocalDeny(row)'),false);
  Object.assign(h.row,{scope:'actor',providerType:'native',configuredPolicy:'ASK',
   active:true,localDenialApplied:false,localDenyEditable:true});
 }
});

test('provider filter catalog counts and exact provider selection',()=>{
 const filterStart=full.indexOf('function isCompositeRow(');
 const filterEnd=full.indexOf('function resetProviderSelections(',filterStart);
 const code=full.slice(filterStart,filterEnd);
 const inventory={providers:[{provider:'sonarcloud'},{provider:'github'},{provider:'mirror'}],
  operations:[{provider:'github',operation:'create_pull_request',configuredPolicy:'ALLOW'},{provider:'github',operation:'merge_pull_request',configuredPolicy:'ASK'},
   {provider:'sonarcloud',operation:'accept_issue',configuredPolicy:'ASK'},
   {provider:'registry',operation:'candidate_head',scope:'exact',currentPolicy:'ALLOW',configuredPolicy:'DENY'}]};
 const ctx=vm.createContext({inventory});
 vm.runInContext(code,ctx);
 const result=vm.runInContext("JSON.stringify({options:providerFilterOptions(inventory),all:visibleProviderRows(inventory,'','').length,github:visibleProviderRows(inventory,'github','').length,ask:visibleProviderRows(inventory,'github','ASK').map(r=>r.operation),none:visibleProviderRows(inventory,'mirror','').length,allowedRegistry:visibleProviderRows(inventory,'registry','allow').length,deniedRegistry:visibleProviderRows(inventory,'registry','deny').length})",ctx);
 assert.deepEqual(JSON.parse(result),{options:[['github',2],['mirror',0],['registry',1],['sonarcloud',1]],all:4,github:2,ask:['merge_pull_request'],none:0,allowedRegistry:1,deniedRegistry:0});
 assert.match(html,/id="providers-select"/);
 inventory.operations.push({provider:'registry',operation:'begin_release_group',operationKind:'composite'});
 const composite=vm.runInContext("JSON.stringify({rows:visibleProviderRows(inventory,'@composite','').map(r=>r.operation),registry:visibleProviderRows(inventory,'registry','').length})",ctx);
 assert.deepEqual(JSON.parse(composite),{rows:['begin_release_group'],registry:1});

});

test('unified editor supports scoped transition, verifies descriptor and never retries finish',async()=>{
 const a=full.indexOf('// Unified V2 editor');
 const z=full.indexOf('// Separate, opt-in local restriction UI.',a);
 const code=full.slice(a,z);
 const elements=new Map(),calls=[];
 const $=id=>{
  if(!elements.has(id))elements.set(id,{value:'',hidden:true,disabled:true,textContent:'',
   children:[],append(x){this.children.push(x);},replaceChildren(){this.children=[];},
   addEventListener(type,callback){this[type]=callback;}});
  return elements.get(id);
 };
 let sentChange=null,failFinish=false,tamper=false,uv=0;
 const row={provider:'github',operation:'create_pull_request',actor:'agent',scope:'actor',
  target:null,currentPolicy:'ASK',editablePolicies:['DENY','ASK','ALLOW'],active:true};
 let inventoryRefreshes=0;
 const context=vm.createContext({$,row,document:{createElement:()=>({})},displayProviderInventory(){},
  loadProviderInventory:async()=>{inventoryRefreshes++;},action:f=>f,
  ceremony:async()=>{uv++;return {test:true};},
  api:async(url,body)=>{
   calls.push({url,body});
   if(url.endsWith('/begin')){
    const c=body.candidate;
    sentChange={...c,purpose:'OWNER_UNIFIED_POLICY_APPLY_V2',requestId:uuid,
     authorityDigest:'a'.repeat(64),sourceDigest:'b'.repeat(64),
     credentialGenerationDigest:'c'.repeat(64),expiresAt:2000};
    return {kind:'OWNER_UNIFIED_POLICY_CEREMONY_V2',ceremonyId:'ceremony',
     options:{publicKey:{userVerification:'required'}},changeDigest:'d'.repeat(64),
     change:tamper?{...sentChange,desiredPolicy:'DENY'}:sentChange,
     preview:{revision:0,oldPolicy:'ASK',newPolicy:'ALLOW',risk:'EXPANDS',
      exactExceptions:0,unresolvedRequests:{},globalRevisionImpact:{}}};
   }
   if(url.endsWith('/finish')&&failFinish)throw Error('lost answer');
   return {found:true,requestId:uuid,appliedRevision:1,currentRevision:1,change:sentChange};
  }});
 const run=x=>vm.runInContext(x,context);
 run("let csrf='owner',tab='providers',providerInventory={policyEditorVersion:2,policyRevision:0,policyVersion:'v|owner-policy-v2:0'},localDenyBusy=false,policyReviewBusy=false; const localDenyCoordinate=/^[A-Za-z0-9_.:-]+$/,localDenyUuid=/^[a-f0-9-]{36}$/;"+code);
 run('unifiedEnabled=true;chooseUnified(row)');
 assert.match($('policy-editor-limits').textContent,/DENY \/ ALLOW/);
 $('policy-editor-scope').value='exact';$('policy-editor-target').value='repo-1';
 $('policy-editor-value').value='ALLOW';$('policy-editor-value').change();
 tamper=true;await assert.rejects(run('prepareUnified()'));assert.equal(uv,0);
 await run('confirmUnified()');assert.equal(uv,0);
 tamper=false;await run('prepareUnified()');
 assert.match($('policy-editor-result').textContent,/РАСШИРЕНИЕ ПРАВ/);
 assert.equal(calls.at(-1).body.candidate.target,'repo-1');
 assert.equal(uv,0);
 failFinish=true;await assert.rejects(run('confirmUnified()'));assert.equal(uv,1);
 assert.match($('policy-editor-result').textContent,/Исход неизвестен/);
 await run('confirmUnified()');assert.equal(calls.filter(c=>c.url.endsWith('/finish')).length,1);
 await run('readbackUnified()');
 assert.equal(inventoryRefreshes,1);
 assert.match($('policy-editor-result').textContent,/Запись исходного UUID подтверждена/);
 assert.equal(run('providerInventory'),null);
});


test('V2 workbench groups rows by provider and selects via radio, not bottom-of-table buttons',()=>{
 assert.match(html,/id="providers-workbench"/);
 assert.match(html,/id="providers-list-pane"/);
 assert.match(html,/id="policy-editor-panel" class="policy-editor" hidden/);
 assert.match(html,/id="providers-editable-only"/);
 const begin=full.indexOf('function inventoryPolicyText(row){');
 const finish=full.indexOf('async function loadProviderInventory(){',begin);
 assert.ok(begin>=0&&finish>begin);
 const els=new Map(),selected=[];
 class Element{
  constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.className='';
   this.value='';this.checked=false;this.disabled=false;}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=[...items];}
 }
 const $=id=>{
  if(!els.has(id))els.set(id,new Element(id));
  return els.get(id);
 };
 const rows=[
  {provider:'github',operation:'create_pull_request',actor:'agent',scope:'actor',
   currentPolicy:'ASK',editablePolicies:['DENY','ASK','ALLOW'],active:true,
   configuredPolicy:'ASK'},
  {provider:'github',operation:'push_commits',actor:'agent',scope:'actor',
   configuredPolicy:'CONDITIONAL',active:true},
  {provider:'workspace',operation:'commit',actor:'agent',scope:'exact',
   target:'repo-1',currentPolicy:'ALLOW',editablePolicies:['DENY','ASK','ALLOW'],active:true,
   configuredPolicy:'DENY'}
 ];
 const context=vm.createContext({$,document:{createElement:tag=>new Element(tag)},
  providerInventory:{policyEditorVersion:2,operations:rows,providers:[{provider:'github'},{provider:'workspace'}]},
  unifiedEnabled:true,unifiedRow:null,
  canSelectUnified:r=>context.unifiedEnabled&&Array.isArray(r.editablePolicies)&&r.editablePolicies.length>1,
  chooseUnified:r=>selected.push(r.operation),
  visibleProviderRows:()=>rows});
 vm.runInContext(full.slice(begin,finish),context);
 context.$('providers-select').value='';
 context.$('providers-filter').value='';
 context.$('providers-editable-only').checked=false;
 vm.runInContext('displayProviderInventory()',context);
 const groups=context.$('providers-results').children;
 assert.equal(groups.length,2);
 assert.equal(groups[0].children[0].textContent,'github · 2');
 const cards=groups[0].children[1].children;
 assert.equal(cards.length,2);
 assert.equal(cards[0].children[0].type,'radio');
 cards[0].children[0].onchange();
 assert.equal(selected[0],'create_pull_request');
 assert.equal(cards[1].children[0].disabled,true);
 assert.match(cards[1].children[1].children[2].textContent,/CONDITIONAL/);
 const exactCard=groups[1].children[1].children[0];
 assert.equal(exactCard.children[1].children[2].textContent,'ALLOW · базовое разрешение');
 context.$('providers-editable-only').checked=true;
 vm.runInContext('displayProviderInventory()',context);
 assert.equal(context.$('providers-summary').textContent,'2 из 3 правил · 2 провайдеров · редактор V2');
 assert.equal(context.$('providers-results').children.length,2);
 // Regression: capability invalidation after WebAuthn must not switch an
 // already V2 inventory back to the legacy table on a provider-filter event.
 context.unifiedEnabled=false;
 context.$('providers-editable-only').checked=false;
 vm.runInContext('displayProviderInventory()',context);
 assert.equal(context.$('providers-results').children[0].tag,'section');
 assert.equal(context.$('providers-results').children[0].children[1].children[0].children[0].disabled,true);
 assert.match(context.$('providers-summary').textContent,/редактор V2/);
});
test('ASK-only native control explains excluded ALLOW and permanent policy vs per-request approval',()=>{
 const begin=full.indexOf('function unifiedChoiceExplanation(');
 const finish=full.indexOf('function canSelectUnified(',begin);
 const ctx=vm.createContext({});
 vm.runInContext(full.slice(begin,finish),ctx);
 const msg=vm.runInContext("unifiedChoiceExplanation({currentPolicy:'ASK',editablePolicies:['DENY','ASK']})",ctx);
 assert.match(msg,/Постоянный ALLOW не допускается/);
 assert.match(msg,/согласования владельца/);
 assert.match(msg,/WebAuthn/);
});
