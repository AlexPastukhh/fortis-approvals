'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const test=require('node:test');

function harness(){
  const elements=new Map(),notifications=[],requests=[],timers=[];
  const state={pending:[],history:[], logged:true, csrf:'known-csrf',permission:'default'};
  class Element{
    constructor(tag){this.tag=tag;this.children=[];this.dataset={};this.hidden=false;this.textContent='';this.value='';
      this.classList={toggle(){}};this.style={setProperty(){}};this.onclick=null;this.onsubmit=null;}
    addEventListener(type,fn){this['on'+type]=fn;}
    setAttribute(name,value){this[name]=value;}
    querySelectorAll(selector){assert.equal(selector,'.detail-actions button');return this.children.filter(e=>e.className==='detail-actions').flatMap(e=>e.children.filter(b=>b.tag==='button'));}
    createTHead(){const head=new Element('thead');this.append(head);return head;}
    insertRow(){const row=new Element('tr');this.append(row);return row;}
    insertCell(){const cell=new Element('td');this.append(cell);return cell;}
    replaceChildren(...args){this.children=[...args];}
    append(...args){this.children.push(...args);}
    get childElementCount(){return this.children.length;}
  }
  const document={documentElement:new Element('html'),title:'Fortis Approvals',hidden:false, createElement:tag=>new Element(tag),
    createTextNode:text=>String(text),addEventListener() {},
    getElementById(id){if(!elements.has(id))elements.set(id,new Element(id));return elements.get(id);}};
  class BrowserNotification{
    static get permission(){return state.permission;}
    static async requestPermission(){state.permission='granted';return state.permission;}
    constructor(title,opts){notifications.push({title,opts});}
  }
  const response=value=>({ok:true,json:async()=>value});
  const fetch=async(url,opts={})=>{
    requests.push({url,opts});
    if(url==='/v1/owner/session')return state.logged?response({owner:'owner',csrf:state.csrf}):{
      ok:false,status:403,json:async()=>({error:'OWNER_SESSION_REQUIRED'})};
    if(url==='/v1/owner/registry/semantic/capabilities')return response(state.semanticCaps??{configured:false});
    if(url==='/v1/owner/registry/semantic/read'&&state.semanticReads){
      const {operation}=JSON.parse(opts.body);
      assert.ok(state.semanticReads[operation]);
      return response({data:state.semanticReads[operation]});
    }
    if(url==='/v1/owner/registry/semantic/discover'){
      if(state.discoveryError)return {ok:false,status:403,json:async()=>({error:'POLICY_DENIED'})};
      return response(state.discoveryRows??[]);
    }
    if(state.registration&&url.startsWith('/v1/owner/registry/semantic/register-')){
      const entry=state.registration, payload=JSON.parse(opts.body);
      assert.equal(opts.headers['X-Fortis-CSRF'],state.csrf);
      assert.equal(payload.requestId,entry.row.requestId);
      assert.equal(url.split('/').at(-2),entry.external?'register-external':'register-confirmed');
      const result={requestId:payload.requestId,state:entry.external?'EXTERNAL_REGISTERED':'EXECUTED'};
      if(url.endsWith('/begin'))return response(entry.settled?result:{
        ceremonyId:'fresh',fingerprint:'d'.repeat(64),mergeSha:'a'.repeat(40),
        options:{publicKey:{challenge:'AQ',userVerification:'required'}}});
      assert.equal(url.split('/').at(-1),'finish');
      assert.deepEqual(payload,{requestId:entry.row.requestId,ceremonyId:'fresh',
        fingerprint:'d'.repeat(64),response:{type:'public-key'}});
      entry.settled=true;
      if(!entry.external){
        entry.row={...entry.row,state:'EXECUTED',mergeRegistrationAvailable:false};
        state.history=state.history.map(row=>row.requestId===entry.row.requestId?entry.row:row);
      }
      return response(result);
    }
    if(state.registration&&url==='/v1/owner/requests/'+state.registration.row.requestId){
      return response(state.registration.row);
    }
    if(url==='/v1/owner/pending')return response(state.pending);
    if(url==='/v1/owner/unresolved')return response({items:[],total:0,truncated:false});
    if(url==='/v1/owner/history')return response(state.history);
    if(url==='/v1/owner/decision/session'){
      const body=JSON.parse(opts.body);
      assert.equal(opts.headers['X-Fortis-CSRF'],state.csrf);
      const index=state.pending.findIndex(r=>r.requestId===body.requestId&&r.fingerprint===body.fingerprint);
      assert.notEqual(index,-1);
      const row=state.pending.splice(index,1)[0];const changed={...row,state:body.decision==='approve'?'EXECUTED':'REJECTED'};
      state.history.push(changed);return response(changed);
    }
    throw Error('Unexpected request '+url);
  };
  const context=vm.createContext({document,window:{Notification:BrowserNotification,focus(){},matchMedia:()=>({matches:false,addEventListener(){}})},
    Notification:BrowserNotification,fetch, setInterval:(f,ms)=>timers.push({f,ms}),
    navigator:{credentials:{async get(options){
      assert.equal(options.publicKey.userVerification,'required');
      state.credentialCalls=(state.credentialCalls??0)+1;
      return {toJSON:()=>({type:'public-key'})};
    }}},PublicKeyCredential:{},isSecureContext:true,
    confirm:()=>true, crypto:require('node:crypto').webcrypto,Uint8Array,atob,btoa,console,Error,Set});
  const js=fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8');
  new vm.Script(js).runInContext(context);
  const flush=async()=>{for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));};
  return {document,state,elements,notifications,requests,timers,flush,run:code=>vm.runInContext(code,context)};
}
const row=id=>({requestId:id,fingerprint:'a'.repeat(64),state:'PENDING',actor:'agent-1',
  request:{service:'synthetic',operation:'set_ask',target:'R3',reason:'demo'},preview:{before:{value:'old'},after:{value:'new'}},
  requiresStrongProof:false,result:null,failure:null});

test('auto-polls pending even while history tab selected and notifies only new arrivals',async()=>{
  const h=harness();await h.flush();
  assert.equal(h.timers.length,1);assert.equal(h.timers[0].ms,5000);
  assert.equal(h.notifications.length,0);
  await h.elements.get('notifications').onclick();
  assert.equal(h.state.permission,'granted');
  const historyButton=h.elements.get('history-tab');await historyButton.onclick();
  h.state.pending.push(row('request-new'));
  await h.timers[0].f();await h.flush();
  assert.equal(h.notifications.length,1);
  assert.equal(h.notifications[0].title,'Fortis Approvals: новая заявка');
  assert.equal(h.document.title,'(1) Fortis Approvals');
  assert.equal(h.elements.get('pending-count').textContent,' · 1');
  await h.timers[0].f();await h.flush();
  assert.equal(h.notifications.length,1,'no duplicates on every refresh');
  assert.equal(h.requests.filter(r=>r.url==='/v1/owner/pending').length>=3,true);
});

test('candidate G4 ASK preview cannot approve while WRITE disabled, but can reject',async()=>{
  const h=harness();await h.flush();
  h.state.pending.push({...row('g4-readonly'),requiresStrongProof:true,approvalAllowed:false,
    request:{service:'sonarcloud',operation:'accept_issue',target:'ISSUE-1',reason:'review'}});
  await h.timers[0].f();await h.flush();
  h.elements.get('requests').children[0].onclick();
  const buttons=h.elements.get('detail').children.find(e=>e.className==='detail-actions').children.filter(e=>e.tag==='button');
  assert.equal(buttons.length,2);
  assert.equal(buttons[0].textContent,'Подтвердить');
  assert.equal(buttons[0].disabled,true);
  assert.equal(buttons[0].onclick,null);
  assert.equal(buttons[1].textContent,'Отклонить');
  assert.equal(typeof buttons[1].onclick,'function');
  assert.equal(h.requests.some(r=>r.url.includes('/v1/owner/decision')),false);
});

test('ordinary approval uses session+CSRF+exact fingerprint, not WebAuthn prompt',async()=>{
  const h=harness();await h.flush();
  h.state.pending.push(row('request-ordinary'));
  await h.timers[0].f();await h.flush();
  const buttons=h.elements.get('requests').children;
  assert.equal(buttons.length,1);
  buttons[0].onclick();
  const decisionButton=h.elements.get('detail').children.find(e=>e.className==='detail-actions').children.find(e=>e.tag==='button'&&e.textContent==='Подтвердить');
  assert.ok(decisionButton);
  await decisionButton.onclick();await h.flush();
  const decision=h.requests.find(r=>r.url==='/v1/owner/decision/session');
  assert.ok(decision,'session endpoint invoked');
  assert.equal(JSON.parse(decision.opts.body).fingerprint,'a'.repeat(64));
  assert.equal(h.state.pending.length,0);
  assert.equal(h.state.history.length,1);
  assert.equal(h.requests.some(r=>r.url==='/v1/owner/decision/begin'),false);
});

test('semantic discovery shows blocked PR reason and clears it on revoked access',async()=>{
 const h=harness();await h.flush();
 h.state.semanticCaps={configured:true,discoveryConfigured:true,repository:'Owner/repo',target:'scope'};
 h.state.discoveryRows=[{number:42,state:'BLOCKED',reason:'CI_NOT_READY'},
                        {requestId:'ready',state:'PENDING'}];
 await h.run('loadSemanticRegistry()');await h.flush();
 const box=h.elements.get('semantic-discovery-status');
 assert.equal(box.hidden,false);
 assert.equal(box.children.length,1);
 assert.equal(box.children[0].children[0].href,'https://github.com/Owner/repo/pull/42');
 assert.match(box.children[0].children[1],/CI не подтверждён/);
 h.state.discoveryError=true;
 await h.run('loadSemanticRegistry()');
 assert.equal(box.children.length,0);
 assert.match(box.textContent,/POLICY_DENIED/);
 h.run("signedOut('session ended')");
 assert.equal(box.hidden,true);
});

test('merge accounting selects exact owner action and external readback does not request another proof',async()=>{
  for(const external of [false,true]){
    const h=harness();
    await h.flush();
    h.state.registration={external,settled:false,row:{...row('merge-request'),
      state:external?'STALE':'UNCERTAIN',failure:external?'MERGE_ALREADY_EXTERNAL':null,
      mergeRegistrationAvailable:!external,request:{service:'release',operation:'merge_and_register',
        target:'pilot',params:{repository:'Owner/repo',number:42,classification:'no-deployment'}}}};
    h.state.history=[h.state.registration.row];
    await h.elements.get('history-tab').onclick();
    h.elements.get('requests').children[0].onclick();
    const detail=h.elements.get('detail');
    const buttons=()=>detail.querySelectorAll('.detail-actions button');
    const label=external?'Зарегистрировать merge из GitHub':'Зарегистрировать подтверждённый merge';
    assert.equal(buttons().some(b=>b.textContent==='Предложить снова'),false);
    const register=()=>buttons().find(b=>b.textContent===label);
    await register().onclick();
    assert.equal(h.elements.get('detail-feedback').textContent,
      'Merge зарегистрирован в Registry.');
    if(external)await register().onclick();
    else assert.equal(register(),undefined);
    const endpoints=h.requests.map(r=>r.url).filter(url=>url.includes('/register-'));
    assert.deepEqual(endpoints.map(url=>url.split('/').at(-1)),external?
      ['begin','finish','begin']:['begin','finish']);
    assert.equal(h.state.credentialCalls,1);
  }
});

test('Registry Board and plan display the catalog restrictions, including across providers',async()=>{
  const h=harness();await h.flush();
  const repository='Owner/repo',subject={repository,targetId:'gateway',environment:'test'};
  const source={sourceSha:'b'.repeat(40)};
  const restrictionDigest='d'.repeat(64);
  const maintenance={beginRequired:true,stateFreeze:true,notes:[],blockedOperations:[
    {service:'github',operation:'merge_pull_request'},{service:'registry',operation:'register_merge'}]};
  h.state.semanticCaps={configured:true,repository,target:'pilot'};
  h.state.semanticReads={
    list_components:{data:{items:[
      {subject,deployable:true,desired:{source},maintenanceProfile:maintenance,restrictionDigest},
      {subject:{...subject,targetId:'legacy'},deployable:false,maintenanceProfile:null}],nextCursor:null}},
    plan_batch:{data:{status:'PLAN_READY',order:[subject],targets:[
      {subject,source,maintenance,restrictionDigest,outstandingActions:[],procedure:'docs/Release.md',
        verification:[]}],buildGroups:[],windowConflicts:[],checks:[]}}
  };
  await h.run('loadSemanticRegistry()');
  h.elements.get('semantic-filter').value='all';
  await h.elements.get('semantic-registry-tab').onclick();
  const table=h.elements.get('semantic-registry-rows').children[0];
  const cells=table.children[1].children;
  const summary=JSON.stringify(cells[1].children.find(node=>node.tag==='details'));
  assert.match(summary,/github\.merge_pull_request, registry\.register_merge/);
  assert.match(summary,/Заморозка состояния/);
  assert.ok(summary.includes(restrictionDigest));
  assert.match(JSON.stringify(table.children[2].children[1]),/Ограничения не подтверждены/);
  cells[0].children[0].checked=true;
  cells[0].children[0].onchange();
  await h.elements.get('semantic-plan').onclick();
  const plan=JSON.stringify(h.elements.get('semantic-registry-result'));
  assert.match(plan,/github\.merge_pull_request, registry\.register_merge/);
  assert.ok(plan.includes(restrictionDigest));
  const reads=h.requests.filter(request=>request.url.endsWith('/semantic/read'));
  assert.deepEqual(reads.map(request=>JSON.parse(request.opts.body).operation),['list_components','plan_batch']);
  assert.equal(h.requests.some(request=>request.url.endsWith('/semantic/submit')),false);
});
