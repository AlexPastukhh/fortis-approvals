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
  configuredPolicy:'ASK',effectivePolicy:'UNKNOWN',localDenialApplied:false};
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
  {active:false},{configuredPolicy:'DENY'},{localDenialApplied:true}
 ]){
  Object.assign(h.row,patch);
  assert.equal(h.run('canSelectLocalDeny(row)'),false);
  Object.assign(h.row,{scope:'actor',providerType:'native',configuredPolicy:'ASK',
   active:true,localDenialApplied:false});
 }
});
