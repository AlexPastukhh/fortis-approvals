'use strict';
const $=id=>document.getElementById(id);
let csrf=null,selected=null,tab='pending',pendingIds=null,pollBusy=false,decisionBusy=false;
let shellConfigured=false,shellBusy=false;
const pollingIntervalMs=5000;
function status(message,error=false){$('status').textContent=message;$('status').classList.toggle('error',error);}
async function api(path,body=null,secured=false){
 const headers={'Accept':'application/json'};
 if(body!==null){headers['Content-Type']='application/json';if(secured)headers['X-Fortis-CSRF']=csrf;}
 const response=await fetch(path,{method:body===null?'GET':'POST',headers,credentials:'same-origin',cache:'no-store',
  ...(body===null?{}:{body:JSON.stringify(body)})});
 const data=await response.json();if(!response.ok){const error=new Error(data.error||`HTTP ${response.status}`);error.httpStatus=response.status;throw error;}
 return data;
}
const decode=text=>Uint8Array.from(atob(text.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const encode=value=>btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
async function ceremony(begin,registration=false){
 if(!isSecureContext||!navigator.credentials)throw Error('WebAuthn требует HTTPS или localhost.');
 const options=begin.options.publicKey;
 let credential;
 if(registration){
  const publicKey=PublicKeyCredential.parseCreationOptionsFromJSON?
    PublicKeyCredential.parseCreationOptionsFromJSON(options):
    {...options,challenge:decode(options.challenge),user:{...options.user,id:decode(options.user.id)},
     excludeCredentials:options.excludeCredentials?.map(v=>({...v,id:decode(v.id)}))};
  credential=await navigator.credentials.create({publicKey});
 }else{
  const publicKey=PublicKeyCredential.parseRequestOptionsFromJSON?
    PublicKeyCredential.parseRequestOptionsFromJSON(options):
    {...options,challenge:decode(options.challenge),allowCredentials:options.allowCredentials?.map(v=>({...v,id:decode(v.id)}))};
  credential=await navigator.credentials.get({publicKey});
 }
 if(!credential)throw Error('Операция отменена.');
 if(credential.toJSON)return credential.toJSON();
 const r=credential.response,standard={id:credential.id,rawId:encode(credential.rawId),type:credential.type,
  clientExtensionResults:credential.getClientExtensionResults()};
 if(registration)return {...standard,response:{clientDataJSON:encode(r.clientDataJSON),
  attestationObject:encode(r.attestationObject),transports:r.getTransports?.()||[]}};
 return {...standard,response:{clientDataJSON:encode(r.clientDataJSON),
  authenticatorData:encode(r.authenticatorData),signature:encode(r.signature),
  userHandle:r.userHandle==null?null:encode(r.userHandle)}};
}
function signedOut(message){
 csrf=null;pendingIds=null;selected=null;document.title='Fortis Approvals';
 $('workspace').hidden=true;$('signin').hidden=false;$('detail').replaceChildren();
 $('powershell-command').value='';$('powershell-result').textContent='Команды ещё не выполнялись.';
 shellConfigured=false;$('powershell-execute').disabled=true;
 if($('policy-review-button'))clearPolicyReview('Сессия владельца завершена.');
 policyPreviewRow=null;providerInventory=null;policyReviewCapabilities=null;
 resetLocalDenyPanel();resetUnifiedPolicyPanel();
 if(message)status(message,true);
}
async function login(){const begin=await api('/v1/login/begin',{});const response=await ceremony(begin);
 const result=await api('/v1/login/finish',{ceremonyId:begin.ceremonyId,response});csrf=result.csrf;
 $('signin').hidden=true;$('registration').hidden=true;$('workspace').hidden=false;status('Вход подтверждён');
 pendingIds=null;await refresh();}
function notifyOnNewPending(rows){
 const next=new Set(rows.map(r=>r.requestId));
 if(pendingIds!==null){
  const added=rows.filter(r=>!pendingIds.has(r.requestId));
  if(added.length){
   status(`Новых заявок: ${added.length}`);
   if('Notification' in window && Notification.permission==='granted'){
    try{const notification=new Notification('Fortis Approvals: новая заявка',
      {body:`Ожидают подтверждения: ${next.size}`,tag:'fortis-pending',renotify:true});
     notification.onclick=()=>{window.focus();notification.close();};}
    catch(_error){/* browser can disable notifications; queue remains visible */}
   }
  }
 }
 pendingIds=next;
 document.title=(next.size?`(${next.size}) `:'')+'Fortis Approvals';
 $('pending-count').textContent=next.size?` · ${next.size}`:'';
}
function render(rows){
 $('requests').replaceChildren();
 for(const row of rows){const btn=document.createElement('button');btn.type='button';btn.dataset.requestId=row.requestId;
  btn.textContent=`${row.request.service} · ${row.request.operation} · ${row.request.target} (${row.state})`;
  btn.onclick=()=>show(row);$('requests').append(btn);}
 if(selected){const matching=rows.find(r=>r.requestId===selected.requestId);
  if(matching && !decisionBusy && (matching.state!==selected.state || matching.fingerprint!==selected.fingerprint))show(matching);
 }
 if(!selected && !$('detail').childElementCount){const p=document.createElement('p');p.textContent='Выберите заявку.';$('detail').append(p);}
}
async function refresh(){
 if(!csrf||pollBusy||decisionBusy)return;
 pollBusy=true;
 try{
  // Always check pending, including while the History tab is selected.
  const pending=await api('/v1/owner/pending');
  notifyOnNewPending(pending);
  let unresolved={items:[],total:0,truncated:false};
  try{
   unresolved=await api('/v1/owner/unresolved');
   $('unresolved-tab').disabled=false;
  }catch(err){
   if(err.httpStatus!==404)throw err;
   // The immutable legacy OwnerPortal may still serve the same static UI.
   // Keep Pending/History usable, but do not misreport an empty incident list.
   $('unresolved-tab').disabled=true;
   if(tab==='unresolved')status('Разбор инцидентов не поддерживается этой версией Portal.',true);
  }
  $('unresolved-count').textContent=unresolved.total?' · '+unresolved.total:'';
  const rows=tab==='pending'?pending:tab==='history'?await api('/v1/owner/history'):
    tab==='unresolved'?unresolved.items:null;
  if(rows!==null)render(rows);
  if(unresolved.truncated && tab==='unresolved')status(
    'Список ограничен 100 записями. Есть ещё блокирующие заявки.',true);
  if(selected&&!decisionBusy){
   const id=selected.requestId;
   const current=await api('/v1/owner/requests/'+id);
   if(selected&&selected.requestId===id&&
     (selected.state!==current.state||selected.fingerprint!==current.fingerprint))show(current);
  }
 }catch(err){if(err.httpStatus===403){signedOut('Сессия истекла — войдите снова.');}
  else status('Нет связи с сервисом: '+err.message,true);
 }finally{pollBusy=false;}
}
function line(label,value){const p=document.createElement('p');const b=document.createElement('strong');b.textContent=label+': ';
 p.append(b,document.createTextNode(String(value??'—')));return p;}
function detailFeedback(message,error=false){
 const element=$('detail-feedback');
 if(element){element.textContent=message;element.classList.toggle('error',error);}
}
function lockDetailActions(locked){
 for(const button of $('detail').querySelectorAll('.detail-actions button')){
  button.disabled=locked||button.dataset.policyDenied==='true';
 }
}
function show(row){
 selected=row;const area=$('detail');area.replaceChildren();
 const h=document.createElement('h2');h.textContent=row.request.service+' · '+row.request.operation;
 area.append(h,line('Состояние',row.state));
 const machinePowerShell=row.request.service==='powershell'&&row.request.operation==='execute';
 if(machinePowerShell){
  const warn=document.createElement('p');
  warn.textContent='⚠ PowerShell от ИИ: произвольная команда под Windows-пользователем. Нет песочницы или автоматической проверки безопасности. Каждое исполнение требует отдельного WebAuthn ASK.';
  area.append(warn,line('Инициатор',row.actor||'—'),line('Windows target',row.request.target));
  area.append(line('SHA256 команды',row.preview?.commandSha256||'—'));
  const label=document.createElement('h3');label.textContent='Полная команда — изучите до решения';
  const command=document.createElement('pre');
  command.textContent=row.request.params?.command||'';
  command.className='machine-command-preview';
  area.append(label,command);
  if(command.textContent.length===0||row.preview?.command!==command.textContent){
   const err=document.createElement('p');
   err.textContent='Команда отсутствует или не совпадает с preview. Подтверждение заблокировано.';
   area.append(err);
  }
 }
 const controls=document.createElement('div');controls.className='detail-actions';
 const feedback=document.createElement('p');feedback.id='detail-feedback';
 feedback.setAttribute('role','status');feedback.setAttribute('aria-live','polite');
 if(row.state==='PENDING'){
  for(const [decision,title] of [['approve','Подтвердить'],['reject','Отклонить']]){
   const btn=document.createElement('button');btn.type='button';btn.textContent=title;
   const invalidMachine=machinePowerShell&&(row.preview?.command!==row.request.params?.command||
     !row.request.params?.command||row.requiresStrongProof!==true);
   if(decision==='approve'&&(row.approvalAllowed===false||invalidMachine)){
    btn.disabled=true;btn.dataset.policyDenied='true';
    btn.title=invalidMachine?'Требуется полный совпадающий preview и WebAuthn':'Подтверждение этой операции отключено';
   }else btn.onclick=action(()=>decide(row,decision));
   controls.append(btn);
  }
 }
 if(['UNCERTAIN','DISPATCHED'].includes(row.state)){
  const btn=document.createElement('button');btn.type='button';
  btn.textContent='Проверить подтверждение (receipt)';
  btn.onclick=action(()=>reconcileUncertain(row));controls.append(btn);
 }
 if(['APPROVED','DISPATCHED','UNCERTAIN','CLOSED_UNCONFIRMED',
     'CANCELLED_BEFORE_DISPATCH'].includes(row.state)){
  const assess=document.createElement('button');assess.type='button';
  assess.textContent='Автопроверка результата';
  assess.title='Только чтение сохранённых событий и receipts, без запуска операции.';
  assess.onclick=action(()=>assessIncident(row));controls.append(assess);
 }
 if(row.state==='APPROVED'){
  const cancel=document.createElement('button');cancel.type='button';
  cancel.textContent='Отменить до выполнения';
  cancel.title='Отмена разрешена только пока Gateway не зафиксировал DISPATCHED.';
  cancel.onclick=action(()=>cancelApproved(row));controls.append(cancel);
 }
 if(row.state==='UNCERTAIN'){
  const close=document.createElement('button');close.type='button';
  close.textContent='Закрыть заявку';
  close.title='Закрыть как CLOSED_UNCONFIRMED. Итог операции не подтверждён.';
  close.onclick=action(()=>closeIncident(row));
  controls.append(close);
 }

 // Machine PowerShell preview precedes any approve control. Existing
 // non-machine actions retain their current ordering and UI behavior.
 area.append(controls,feedback);
 if(row.state==='UNCERTAIN')detailFeedback(
  'Результат неизвестен: действие могло выполниться. Не повторяйте его. Проверка receipt ничего не запускает.',true);
 else if(row.state==='DISPATCHED')detailFeedback(
  'Операция передана исполнителю. Её не следует повторять.');
 else if(row.state==='APPROVED')detailFeedback(
  'Решение принято, выполнение ещё не подтверждено.');
 else if(row.state==='PENDING'){
  if(row.approvalAllowed===false)detailFeedback('Подтверждение недоступно; можно только отклонить.',true);
  else if(row.requiresStrongProof)detailFeedback('Для подтверждения потребуется ключ безопасности.');
 }
 else if(row.state==='CLOSED_UNCONFIRMED')detailFeedback(
  'Расследование закрыто владельцем. Итог исходной операции НЕ доказан; не повторяйте её вслепую.',true);
 else if(row.state==='CANCELLED_BEFORE_DISPATCH')detailFeedback(
  'Отменено до DISPATCHED. Этот UUID не исполнялся; новое действие допускается лишь с новым UUID и актуальными проверками.');
 if(row.incidentClosure){
  const evidence=row.incidentClosure;
  if(evidence.backupVolumeOwnerAttested)area.append(
    line('Резервная копия (указана владельцем)',evidence.backupVolumeOwnerAttested));
  if(evidence.explanation)area.append(line('Обоснование закрытия',evidence.explanation));
  if(evidence.closeMethod==='authenticated_owner_session')area.append(
    line('Закрыто','Владельцем без подтверждения результата операции'));
 }

 area.append(line('Инициатор',row.actor||'проверенный клиент'),
  line('Объект',row.request.target),line('Причина',row.request.reason),line('ID',row.requestId));
 const label=document.createElement('h3');label.textContent='Точное изменение и состояние';area.append(label);
 const preview=document.createElement('pre');preview.textContent=
   JSON.stringify({request:row.request,preview:row.preview},null,2);area.append(preview);
 if(row.result){const p=document.createElement('pre');p.textContent=
  'Результат: '+JSON.stringify(row.result,null,2);area.append(p);}
 if(row.failure)area.append(line('Причина остановки',row.failure));
}
function decisionMessage(result){
 const id=result.requestId;
 if(result.state==='EXECUTED')return 'Заявка '+id+': выполнение подтверждено.';
 if(result.state==='REJECTED')return 'Заявка '+id+': отклонена. Действие не отправлялось.';
 if(result.state==='UNCERTAIN')return 'Заявка '+id+': результат неизвестен. Не повторяйте действие.';
 if(['APPROVED','DISPATCHED'].includes(result.state))return
  'Решение по '+id+' принято; выполнение ещё не подтверждено ('+result.state+').';
 return 'Заявка '+id+': состояние '+result.state+'.';
}
async function decide(row,decision){
 if(decisionBusy)return;
 decisionBusy=true;lockDetailActions(true);
 detailFeedback(decision==='approve'?'Подтверждение в процессе. Не нажимайте повторно.':
  'Отклонение в процессе. Не нажимайте повторно.');
 try{
  let result;
  if(row.requiresStrongProof){
   const begin=await api('/v1/owner/decision/begin',{requestId:row.requestId,decision},true);
   detailFeedback('Ожидается подтверждение ключом безопасности…');
   const response=await ceremony(begin);
   detailFeedback('Решение отправлено. Проверяю результат…');
   result=await api('/v1/owner/decision/finish',{requestId:row.requestId,decision,
      ceremonyId:begin.ceremonyId,response},true);
  }else{
   detailFeedback('Отправляю решение и ожидаю ответ…');
   result=await api('/v1/owner/decision/session',{
     requestId:row.requestId,fingerprint:row.fingerprint,decision},true);
  }
  show(result);const message=decisionMessage(result);
  detailFeedback(message,result.state==='UNCERTAIN');
  status(message,result.state==='UNCERTAIN');
 }catch(err){
  detailFeedback('Ответ не подтверждён. Проверяю заявку '+row.requestId+
    '. Не отправляйте решение повторно.',true);
  try{
   const exact=await api('/v1/owner/requests/'+row.requestId);
   show(exact);detailFeedback('Текущее состояние '+row.requestId+': '+exact.state,
      exact.state==='UNCERTAIN');
  }catch(_readError){lockDetailActions(true);}
  throw err;
 }finally{decisionBusy=false;await refresh();}
}
async function reconcileUncertain(row){
 if(decisionBusy)return;
 decisionBusy=true;lockDetailActions(true);
 detailFeedback('Проверяю сохранённый receipt. Повторного выполнения не будет.');
 try{
  const result=await api('/v1/owner/reconcile',{requestId:row.requestId},true);
  show(result);
  const message=result.state==='EXECUTED'?
   'Сохранённый receipt подтверждён. Операция помечена выполненной.':
   'Подтверждённый receipt не найден. Заявка остаётся '+result.state+
     '; нельзя объявить её успешной или повторять.';
  detailFeedback(message,result.state!=='EXECUTED');
  status(message,result.state!=='EXECUTED');
 }catch(err){
  detailFeedback('Сверка не завершилась: '+err.message+'. Не повторяйте исходную операцию.',true);
  throw err;
 }finally{decisionBusy=false;await refresh();}
}
async function closeIncident(row){
 if(decisionBusy)return;
 decisionBusy=true;lockDetailActions(true);
 detailFeedback('Закрываю заявку. Итог исходной операции останется неизвестным…');
 try{
  const result=await api('/v1/owner/incidents/close/simple',
   {requestId:row.requestId,fingerprint:row.fingerprint},true);
  show(result);
  status('Заявка '+row.requestId+' закрыта. Результат операции не подтверждён.');
  detailFeedback('CLOSED_UNCONFIRMED: повторного исполнения не было.');
 }catch(err){
  try{
   const actual=await api('/v1/owner/requests/'+row.requestId);
   show(actual);
   detailFeedback('Текущее состояние после ошибки: '+actual.state+'.',true);
  }catch(_lookup){lockDetailActions(true);}
  throw err;
 }finally{decisionBusy=false;await refresh();}
}
async function assessIncident(row){
 if(decisionBusy)return;
 decisionBusy=true;lockDetailActions(true);
 detailFeedback('Проверяю только сохранённый audit, worker и receipt. Ничего не исполняется.');
 try{
  const result=await api('/v1/owner/incidents/assess',{requestId:row.requestId},true);
  const descriptions={
   VERIFIED_NOT_DISPATCHED:'Отмена подтверждена: исходный Gateway не передавал операцию исполнителю. Новый запрос требует свежих условий и UUID.',
   CANCELLABLE_IF_STILL_APPROVED:'Заявка пока APPROVED без записи DISPATCHED. Можно попытаться отменить; повторная проверка произойдёт атомарно.',
   CORE_EXECUTION_CONFIRMED:'Gateway записал подтверждённое EXECUTED. Повторять действие не нужно.',
   RECEIPT_PRESENT_RECONCILE_REQUIRED:'Есть сохранённый receipt. Можно сверить подтверждение; исходная операция не повторится.',
   RECEIPT_AFTER_CLOSURE_REVIEW_REQUIRED:'После административного закрытия обнаружена квитанция. Нужен отдельный разбор; нельзя автоматически менять исход.',
   OUTCOME_UNCONFIRMED:'Достоверного подтверждения нет. Нужны дополнительные независимые проверки, автоматический повтор запрещён.'
  };
  const message=descriptions[result.verdict]||'Статус проверки: '+result.verdict;
  detailFeedback(message,result.verdict==='OUTCOME_UNCONFIRMED');
  status(message,result.verdict==='OUTCOME_UNCONFIRMED');
 }catch(err){
  detailFeedback('Автопроверка не завершена: '+err.message+'. Не повторяйте действие.',true);
  throw err;
 }finally{decisionBusy=false;await refresh();}
}
async function cancelApproved(row){
 if(decisionBusy)return;
 decisionBusy=true;lockDetailActions(true);
 detailFeedback('Пытаюсь отменить только если состояние всё ещё APPROVED…');
 try{
  const result=await api('/v1/owner/incidents/cancel/approved',
   {requestId:row.requestId,fingerprint:row.fingerprint},true);
  show(result);
  const message='Заявка '+row.requestId+
   ' отменена до DISPATCHED. Исходный UUID не исполнять; для новой попытки нужен новый запрос.';
  detailFeedback(message);status(message);
 }catch(err){
  try{
   const actual=await api('/v1/owner/requests/'+row.requestId);
   show(actual);
   detailFeedback('Отмена не подтверждена. Текущее состояние: '+actual.state+
    '. Если DISPATCHED/UNCERTAIN — сначала проверить результат.',true);
  }catch(_lookup){lockDetailActions(true);}
  throw err;
 }finally{decisionBusy=false;await refresh();}
}
async function allowNotifications(){
 if(!('Notification' in window)){status('Этот браузер не поддерживает уведомления.',true);return;}
 if(Notification.permission==='denied'){status('Уведомления заблокированы в настройках браузера.',true);return;}
 const permission=await Notification.requestPermission();
 status(permission==='granted'?'Уведомления включены для открытой вкладки.':'Уведомления не разрешены.',permission!=='granted');
}
function action(fn){return async e=>{e?.preventDefault?.();try{await fn(e);}catch(err){
 if(err.httpStatus===403 && err.message==='OWNER_SESSION_REQUIRED'){signedOut('Сессия истекла — войдите снова.');}
 else status(err.message,true);
}};}
$('login').onclick=action(login);
$('show-enroll').onclick=()=>{$('registration').hidden=!$('registration').hidden;};
$('enroll').onsubmit=action(async()=>{const begin=await api('/v1/enroll/begin',{invitation:$('invitation').value});
 const response=await ceremony(begin,true);await api('/v1/enroll/finish',{ceremonyId:begin.ceremonyId,response});
 $('invitation').value='';$('registration').hidden=true;status('Ключ зарегистрирован. Теперь войдите.');});
function switchWorkspaceTab(which){
 if(which!=='providers'){resetLocalDenyPanel();resetUnifiedPolicyPanel();}
 tab=which;
 $('approval-view').hidden=which==='powershell'||which==='providers';
 $('powershell-view').hidden=which!=='powershell';
 $('providers-view').hidden=which!=='providers';
 for(const id of ['pending','unresolved','history','powershell','providers']){
  $(''+id+'-tab').setAttribute('aria-pressed',String(which===id));
 }
}
async function loadOwnerShell(){
 const caps=await api('/v1/owner/powershell/capabilities');
 shellConfigured=caps.configured===true;
 $('powershell-availability').textContent=shellConfigured ?
  'Исполнитель сконфигурирован. Команды выполняются на Windows без Analyzer.' :
  'Windows Executor пока не подключён. Выполнение команд недоступно.';
 $('powershell-execute').disabled=!shellConfigured||shellBusy;
}
async function ownerPowerShellExecute(){
 if(!csrf||shellBusy||!shellConfigured)return;
 const command=$('powershell-command').value;
 if(!command.trim())throw Error('Вставьте команду PowerShell.');
 if(new TextEncoder().encode(command).length>8192)throw Error('Команда превышает ограничение 8 КиБ.');
 const requestId=crypto.randomUUID();
 shellBusy=true;$('powershell-execute').disabled=true;
 $('powershell-result').textContent='Выполнение на Windows…\nRequest ID: '+requestId;
 try{
  const result=await api('/v1/owner/powershell/execute',{command,requestId},true);
  $('powershell-result').textContent=[
   'Request ID: '+requestId,
   'Состояние: '+result.state,
   'SHA256 команды: '+(result.commandSha256||'—'),
   'Exit code: '+(result.exitCode??'—'),
   '', 'STDOUT:', result.stdout??'—', '', 'STDERR:', result.stderr??'—',
   result.stdoutTruncated||result.stderrTruncated ? 'ВЫВОД ОБРЕЗАН' : ''
  ].join('\n');
  status(result.state==='EXECUTED'?'Команда выполнена.':'Команда: '+result.state,
   result.state!=='EXECUTED');
 }catch(err){
  $('powershell-result').textContent='Результат неизвестен. Не повторяйте запрос автоматически.\n'+
   'Request ID: '+requestId+'\n'+err.message;
  throw err;
 }finally{shellBusy=false;$('powershell-execute').disabled=!shellConfigured;}
}
$('pending-tab').onclick=action(async()=>{switchWorkspaceTab('pending');selected=null;$('detail').replaceChildren();await refresh();});
$('history-tab').onclick=action(async()=>{switchWorkspaceTab('history');selected=null;$('detail').replaceChildren();await refresh();});
$('unresolved-tab').onclick=action(async()=>{switchWorkspaceTab('unresolved');selected=null;$('detail').replaceChildren();await refresh();});
$('powershell-tab').onclick=action(async()=>{switchWorkspaceTab('powershell');await loadOwnerShell();});
let policyPreviewRow=null;
let providerInventory=null;
let policyPreviewCandidate=null,policyReviewCapabilities=null,policyReviewBusy=false;
function clearPolicyReview(message='Для подтверждения сначала выполните предпросмотр.'){
 policyPreviewCandidate=null;
 $('policy-review-button').disabled=true;
 $('policy-review-output').textContent=message;
}

// Unified V2 editor is never enabled by source presence. Inventory and a
// separate owner-only capability must both confirm the installed authority.
const unifiedPrefix='/v1/owner/policy/editor';
const unifiedValues=['DENY','ASK','ALLOW'];
let unifiedEnabled=false,unifiedRow=null,unifiedPrepared=null,unifiedUnknown=null,unifiedBusy=false,unifiedEpoch=0;
function unifiedSame(epoch,session){
 return !!session&&csrf===session&&tab==='providers'&&unifiedEnabled&&unifiedEpoch===epoch;
}
function updateUnifiedControls(){
 const available=!!csrf&&tab==='providers'&&unifiedEnabled;
 const edit=available&&!unifiedBusy&&!unifiedUnknown&&!!unifiedRow;
 const exact=$('policy-editor-scope').value==='exact';
 $('policy-editor-scope').disabled=!edit||unifiedRow.scope!=='actor';
 $('policy-editor-target').disabled=!edit||!exact||unifiedRow.scope==='exact';
 $('policy-editor-value').disabled=!edit;
 $('policy-editor-prepare').disabled=!edit||!unifiedCandidate();
 $('policy-editor-confirm').disabled=!edit||!unifiedPrepared;
 $('policy-editor-readback').disabled=!available||unifiedBusy||!unifiedUnknown;
}
function resetUnifiedPolicyPanel(){
 unifiedEpoch++;unifiedEnabled=false;unifiedRow=null;unifiedPrepared=null;
 $('policy-editor-panel').hidden=true;
 $('policy-editor-selection').textContent='Выберите изменяемую операцию в списке слева.';
 $('policy-editor-limits').textContent='Разрешённые переходы определяет сервер.';
 $('policy-editor-result').textContent='';
 updateUnifiedControls();
}
function unifiedChoiceExplanation(row){
 const values=row.editablePolicies, choices=values.filter(policy=>policy!==row.currentPolicy);
 const transition=choices.length?choices.join(' / '):'нет';
 if(values.includes('ASK')&&!values.includes('ALLOW'))
  return 'Возможный переход: '+transition+'. Постоянный ALLOW не допускается текущим контрактом операции: будущие запросы ИИ требуют отдельного согласования владельца. Подтверждение смены правила через WebAuthn не заменяет эти решения.';
 if(values.includes('ALLOW')&&!values.includes('ASK'))
  return 'Возможный переход: '+transition+'. Этот синхронный READ не поддерживает очередь ASK.';
 return 'Возможные переходы: '+transition+'. Точечные исключения и прочие ограничения операции сохраняются.';
}
function canSelectUnified(row){
 return unifiedEnabled&&!!row&&row.active===true&&
  ['actor','exact'].includes(row.scope)&&unifiedValues.includes(row.currentPolicy)&&
  Array.isArray(row.editablePolicies)&&row.editablePolicies.every(p=>unifiedValues.includes(p))&&
  row.editablePolicies.some(p=>p!==row.currentPolicy);
}
function unifiedCandidate(){
 if(!unifiedRow||!canSelectUnified(unifiedRow)||!providerInventory)return null;
 const row=unifiedRow,scope=$('policy-editor-scope').value;
 const target=scope==='exact'?$('policy-editor-target').value:null;
 const desiredPolicy=$('policy-editor-value').value;
 if(!['actor','exact'].includes(scope)||(row.scope==='exact'&&(scope!=='exact'||target!==row.target))||
    (scope==='exact'&&!localDenyCoordinate.test(target))||
    !row.editablePolicies.includes(desiredPolicy)||desiredPolicy===row.currentPolicy)return null;
 return {actor:row.actor,provider:row.provider,operation:row.operation,scope,target,
  expectedPolicy:row.currentPolicy,desiredPolicy,expectedRevision:providerInventory.policyRevision,
  expectedPolicyVersion:providerInventory.policyVersion,reasonCode:'OWNER_POLICY_CHANGE'};
}
function chooseUnified(row){
 if(unifiedBusy||unifiedUnknown||!canSelectUnified(row))return;
 unifiedEpoch++;unifiedPrepared=null;unifiedRow=row;
 $('policy-editor-selection').textContent=[row.provider,row.operation,'Actor: '+row.actor,
   row.target??'Все target','Сейчас: '+row.currentPolicy].join(' · ');
 $('policy-editor-limits').textContent=unifiedChoiceExplanation(row);
 $('policy-editor-scope').value=row.scope;
 $('policy-editor-target').value=row.target??'';
 const select=$('policy-editor-value');select.replaceChildren();
 for(const policy of unifiedValues){
  if(!row.editablePolicies.includes(policy)||policy===row.currentPolicy)continue;
  const option=document.createElement('option');option.value=policy;option.textContent=policy;select.append(option);
 }
 select.value=unifiedValues.find(p=>row.editablePolicies.includes(p)&&p!==row.currentPolicy)??'';
 $('policy-editor-result').textContent='Проверьте параметры и последствия. Права ещё не изменены.';
 updateUnifiedControls();
}
function verifiedUnifiedBegin(begin,candidate){
 const change=begin?.change;
 return begin?.kind==='OWNER_UNIFIED_POLICY_CEREMONY_V2'&&
  typeof begin.ceremonyId==='string'&&!!begin.ceremonyId&&
  /^[a-f0-9]{64}$/.test(begin.changeDigest)&&
  begin.options?.publicKey?.userVerification==='required'&&
  change?.purpose==='OWNER_UNIFIED_POLICY_APPLY_V2'&&
  Object.keys(change).length===Object.keys(candidate).length+6&&
  Object.keys(candidate).every(k=>candidate[k]===change[k])&&
  localDenyUuid.test(change.requestId)&&Number.isSafeInteger(change.expiresAt)&&
  ['authorityDigest','sourceDigest','credentialGenerationDigest'].every(k=>/^[a-f0-9]{64}$/.test(change[k]))&&
  begin.preview?.revision===candidate.expectedRevision&&
  begin.preview?.oldPolicy===candidate.expectedPolicy&&begin.preview?.newPolicy===candidate.desiredPolicy&&
  ['EXPANDS','RESTRICTS'].includes(begin.preview?.risk);
}
async function prepareUnified(){
 if(unifiedBusy||unifiedUnknown||localDenyBusy||policyReviewBusy||!csrf)return;
 const candidate=unifiedCandidate();
 if(!candidate)return;
 const epoch=++unifiedEpoch,session=csrf;
 unifiedPrepared=null;unifiedBusy=true;updateUnifiedControls();
 try{
  const begin=await api(unifiedPrefix+'/begin',{candidate},true);
  if(!unifiedSame(epoch,session))return;
  if(!verifiedUnifiedBegin(begin,candidate))throw Error('Описание изменения не соответствует выбранному правилу.');
  unifiedPrepared={begin,epoch,session};
  $('policy-editor-result').textContent=[
   [candidate.provider,candidate.operation,candidate.actor,candidate.target??'Правило метода'].join(' · '),
   candidate.expectedPolicy+' → '+candidate.desiredPolicy,
   begin.preview.risk==='EXPANDS'?'РАСШИРЕНИЕ ПРАВ: метод может получить дополнительные полномочия.':'Ограничение прав.',
   'Точечные исключения сохраняются: '+begin.preview.exactExceptions,
   'Незавершённые заявки этого правила: '+JSON.stringify(begin.preview.unresolvedRequests),
   'Общая ревизия изменится. PENDING/APPROVED требуют нового рассмотрения: '+JSON.stringify(begin.preview.globalRevisionImpact),
   'UUID: '+begin.change.requestId,
   'Права не изменены. Для применения необходимо отдельное подтверждение WebAuthn.'
  ].join('\n');
 }catch(err){
  if(unifiedSame(epoch,session))$('policy-editor-result').textContent=err.message;
  throw err;
 }finally{unifiedBusy=false;updateUnifiedControls();}
}
function unifiedReceiptMatches(result,change){
 return result?.found===true&&result.requestId===change.requestId&&
  result.appliedRevision===change.expectedRevision+1&&Number.isSafeInteger(result.currentRevision)&&
  result.currentRevision>=result.appliedRevision&&
  result.change&&Object.keys(result.change).length===Object.keys(change).length&&
  Object.keys(change).every(k=>result.change[k]===change[k]);
}
async function confirmUnified(){
 const prepared=unifiedPrepared;
 if(!prepared||unifiedBusy||unifiedUnknown||!unifiedSame(prepared.epoch,prepared.session))return;
 const {begin,epoch,session}=prepared;
 unifiedPrepared=null;unifiedBusy=true;updateUnifiedControls();
 let sent=false;
 try{
  const response=await ceremony(begin);
  if(!unifiedSame(epoch,session))return;
  unifiedUnknown=begin.change;sent=true;
  const result=await api(unifiedPrefix+'/finish',{ceremonyId:begin.ceremonyId,response,change:begin.change},true);
  if(!unifiedReceiptMatches(result,begin.change))throw Error('Запись не подтверждена.');
  unifiedUnknown=null;unifiedRow=null;unifiedEnabled=false;
  if(csrf===session&&tab==='providers')$('policy-editor-result').textContent='Изменение подтверждено. UUID: '+result.requestId+
   '. Ревизия: '+result.appliedRevision+'. Обновите инвентарь.';
 }catch(err){
  if(unifiedSame(epoch,session))$('policy-editor-result').textContent=sent?
   'Исход неизвестен. UUID: '+begin.change.requestId+'. Используйте проверку UUID, не повторяйте изменение.':
   'WebAuthn не завершён. Изменение не отправлено.';
  throw err;
 }finally{unifiedBusy=false;updateUnifiedControls();}
}
async function readbackUnified(){
 if(!unifiedUnknown||unifiedBusy||!unifiedEnabled||!csrf||tab!=='providers')return;
 const change=unifiedUnknown,epoch=unifiedEpoch,session=csrf;
 unifiedBusy=true;updateUnifiedControls();
 try{
  const result=await api(unifiedPrefix+'/readback',{requestId:change.requestId},true);
  if(!unifiedSame(epoch,session))return;
  if(!unifiedReceiptMatches(result,change)){
   $('policy-editor-result').textContent='Исход не подтверждён. Не повторяйте изменение. UUID: '+change.requestId;return;
  }
  unifiedUnknown=null;unifiedRow=null;unifiedEnabled=false;
  $('policy-editor-result').textContent='Запись исходного UUID подтверждена. Обновите инвентарь.';
 }finally{unifiedBusy=false;updateUnifiedControls();}
}
for(const id of ['policy-editor-scope','policy-editor-target','policy-editor-value']){
 $(id).addEventListener(id==='policy-editor-target'?'input':'change',()=>{
  unifiedEpoch++;unifiedPrepared=null;updateUnifiedControls();
 });
}
$('policy-editor-prepare').onclick=action(prepareUnified);
$('policy-editor-confirm').onclick=action(confirmUnified);
$('policy-editor-readback').onclick=action(readbackUnified);


// Separate, opt-in local restriction UI. Server WebAuthn/CAS is the authority.
const localDenyPrefix='/v1/owner/policy/local-deny';
const localDenyCoordinate=/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/;
const localDenyUuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
let localDenyEnabled=false,localDenyRow=null,localDenyPrepared=null;
let localDenyBusy=false,localDenyEpoch=0,localDenyUnknown=null;

function updateLocalDenyControls(){
 const available=!!csrf&&tab==='providers'&&localDenyEnabled;
 const editable=available&&!localDenyBusy&&!localDenyUnknown&&!!localDenyRow;
 $('local-deny-target').disabled=!editable||localDenyRow.scope!=='actor';
 $('local-deny-prepare').disabled=!editable||!localDenyCoordinate.test($('local-deny-target').value);
 $('local-deny-confirm').disabled=!editable||!localDenyPrepared;
 $('local-deny-readback').disabled=!available||localDenyBusy||!localDenyUnknown;
}
function resetLocalDenyPanel(){
 localDenyEpoch++;localDenyEnabled=false;localDenyRow=null;localDenyPrepared=null;
 $('local-deny-panel').hidden=true;
 $('local-deny-selection').textContent='Выберите доступное правило.';
 $('local-deny-target').value='';
 $('local-deny-result').textContent='';
 updateLocalDenyControls();
}
function localDenySnapshotValid(){
 return !!providerInventory&&providerInventory.localDenyOnly===true&&
  Number.isSafeInteger(providerInventory.localPolicyRevision)&&providerInventory.localPolicyRevision>=0&&
  typeof providerInventory.policyVersion==='string'&&
  providerInventory.policyVersion.endsWith('|owner-local-deny:'+providerInventory.localPolicyRevision);
}
async function loadLocalDenyCapabilities(session,epoch){
 try{
  const caps=await api(localDenyPrefix+'/capabilities');
  if(!session||csrf!==session||tab!=='providers'||epoch!==localDenyEpoch)return;
  localDenyEnabled=localDenySnapshotValid()&&caps.configured===true&&
   caps.kind==='OWNER_LOCAL_EXACT_DENY_ONLY'&&caps.ownerOnly===true&&
   caps.requiresFreshStrongWebAuthn===true&&caps.canGrantAllow===false&&caps.canRemoveDenial===false;
 }catch(error){
  if(!session||csrf!==session||tab!=='providers'||epoch!==localDenyEpoch)return;
  localDenyEnabled=false;
 }
 $('local-deny-panel').hidden=!localDenyEnabled;
 if(localDenyEnabled&&localDenyUnknown){
  $('local-deny-result').textContent='Исход предыдущего применения не подтверждён. UUID: '+localDenyUnknown.requestId+
   '. Проверьте исходный UUID; не повторяйте применение.';
 }
 updateLocalDenyControls();
}
function canSelectLocalDeny(row){
 return localDenyEnabled&&localDenySnapshotValid()&&row.providerType==='native'&&
  row.active===true&&row.configured===true&&row.localDenialApplied===false&&
  row.localDenyEditable===true&&
  ['ASK','ALLOW'].includes(row.configuredPolicy)&&
  [row.actor,row.provider,row.operation].every(x=>typeof x==='string'&&localDenyCoordinate.test(x))&&
  (row.scope==='actor'||(row.scope==='exact'&&typeof row.target==='string'&&
   localDenyCoordinate.test(row.target)&&row.effectivePolicy===row.configuredPolicy));
}
function selectLocalDeny(row){
 if(localDenyBusy||localDenyUnknown||!canSelectLocalDeny(row))return;
 localDenyEpoch++;localDenyPrepared=null;localDenyRow=row;
 $('local-deny-selection').textContent=[row.actor,row.provider,row.operation,
  'Настроено: '+row.configuredPolicy,'Источник: '+row.scope].join(' · ');
 $('local-deny-target').value=row.scope==='exact'?row.target:'';
 $('local-deny-result').textContent='Будет ограничен только указанный target. Подготовка ничего не сохраняет.';
 updateLocalDenyControls();
}
function sameLocalDenySession(epoch,session){
 return !!session&&csrf===session&&tab==='providers'&&localDenyEnabled&&epoch===localDenyEpoch;
}
function verifiedLocalDenyBegin(begin,candidate){
 const c=begin?.change;
 return begin?.kind==='OWNER_LOCAL_DENY_APPLY_CEREMONY'&&begin.newPolicy==='DENY'&&
  begin.runtimeIntegrated===false&&typeof begin.ceremonyId==='string'&&!!begin.ceremonyId&&
  typeof begin.changeDigest==='string'&&/^[0-9a-f]{64}$/.test(begin.changeDigest)&&
  begin.options?.publicKey?.userVerification==='required'&&c&&
  c.purpose==='OWNER_LOCAL_EXACT_DENY_APPLY_V1'&&c.newPolicy==='DENY'&&
  typeof c.requestId==='string'&&localDenyUuid.test(c.requestId)&&
  Number.isSafeInteger(c.expiresAt)&&
  Object.keys(candidate).every(k=>c[k]===candidate[k])&&
  c.expectedConfiguredScope===candidate.expectedConfiguredScope&&
  Object.keys(c).length===Object.keys(candidate).length+6&&
  typeof c.sourceDigest==='string'&&/^[0-9a-f]{64}$/.test(c.sourceDigest)&&
  typeof c.credentialGenerationDigest==='string'&&/^[0-9a-f]{64}$/.test(c.credentialGenerationDigest);
}
async function prepareLocalDeny(){
 if(localDenyBusy||policyReviewBusy||localDenyUnknown||!localDenyRow||
    !canSelectLocalDeny(localDenyRow)||!csrf||tab!=='providers')return;
 const row=localDenyRow,target=$('local-deny-target').value;
 if(!localDenyCoordinate.test(target)||(row.scope==='exact'&&target!==row.target))return;
 const epoch=++localDenyEpoch,session=csrf;
 const candidate={actor:row.actor,provider:row.provider,operation:row.operation,target,
  expectedConfiguredPolicy:row.configuredPolicy,expectedPolicyVersion:providerInventory.policyVersion,
  expectedRevision:providerInventory.localPolicyRevision,reasonCode:'OWNER_DENY_EXACT'};
 if(row.scope==='actor')candidate.expectedConfiguredScope='actor';
 localDenyPrepared=null;localDenyBusy=true;updateLocalDenyControls();
 try{
  const begin=await api(localDenyPrefix+'/begin',{candidate},true);
  if(!sameLocalDenySession(epoch,session))return;
  if(!verifiedLocalDenyBegin(begin,candidate))throw Error('Неожиданное описание WebAuthn. Операция остановлена.');
  localDenyPrepared={begin,epoch,session};
  $('local-deny-result').textContent=[
   'Actor: '+candidate.actor,'Провайдер: '+candidate.provider,'Метод: '+candidate.operation,
   'Точный target: '+candidate.target,'Изменение: '+candidate.expectedConfiguredPolicy+' → DENY',
   'Источник: '+row.scope+'; другие target не изменяются.',
   'Ревизия: '+candidate.expectedRevision+'; UUID: '+begin.change.requestId,
   'Изменение ещё не применено. Подтвердите только этот локальный запрет.'
  ].join('\n');
 }catch(error){
  if(sameLocalDenySession(epoch,session))$('local-deny-result').textContent='Подготовка отклонена: '+error.message;
  throw error;
 }finally{localDenyBusy=false;updateLocalDenyControls();}
}
async function confirmLocalDeny(){
 const prepared=localDenyPrepared;
 if(!prepared||localDenyBusy||policyReviewBusy||localDenyUnknown||
    !sameLocalDenySession(prepared.epoch,prepared.session))return;
 localDenyPrepared=null;localDenyBusy=true;updateLocalDenyControls();
 const {begin,epoch,session}=prepared;
 let sent=false;
 try{
  const response=await ceremony(begin);
  if(!sameLocalDenySession(epoch,session))return;
  // Set the uncertainty marker BEFORE sending finish. Never retry finish.
  localDenyUnknown={requestId:begin.change.requestId,expectedRevision:begin.change.expectedRevision};
  sent=true;
  const result=await api(localDenyPrefix+'/finish',{ceremonyId:begin.ceremonyId,
   change:begin.change,response},true);
  if(result.kind!=='OWNER_LOCAL_DENY_ONLY_COMMIT'||result.requestId!==begin.change.requestId||
     result.localDenyCommitted!==true||result.runtimeIntegrated!==false||
     result.canGrantAllow!==false||result.newPolicy!=='DENY'||
     result.oldPolicy!==begin.change.expectedConfiguredPolicy||
     result.appliedRevision!==begin.change.expectedRevision+1||
     !Number.isSafeInteger(result.currentRevision)||result.currentRevision<result.appliedRevision){
   throw Error('Ответ не подтверждает запись.');
  }
  localDenyUnknown=null;
  if(sameLocalDenySession(epoch,session)){
   localDenyRow=null;localDenyEnabled=false;
   displayProviderInventory();
   $('local-deny-result').textContent='Локальная запись DENY подтверждена. UUID: '+result.requestId+
     '. Ревизия: '+result.appliedRevision+'. Обновите инвентаризацию; защита всех процессов не подтверждена.';
  }
 }catch(error){
  if(sameLocalDenySession(epoch,session))$('local-deny-result').textContent=sent?
   'Исход неизвестен. UUID: '+begin.change.requestId+'. Используйте проверку UUID, не повторяйте применение.':
   'WebAuthn не завершён; запрос finish не отправлен. Подготовьте новый запрос.';
  throw error;
 }finally{localDenyBusy=false;updateLocalDenyControls();}
}
async function readbackLocalDeny(){
 if(!localDenyUnknown||localDenyBusy||!localDenyEnabled||!csrf||tab!=='providers')return;
 const unknown=localDenyUnknown,epoch=localDenyEpoch,session=csrf;
 localDenyBusy=true;updateLocalDenyControls();
 try{
  const result=await api(localDenyPrefix+'/readback',{requestId:unknown.requestId},true);
  if(!sameLocalDenySession(epoch,session))return;
  if(result.requestId!==unknown.requestId||result.runtimeIntegrated!==false||
     result.found!==true||result.appliedRevision!==unknown.expectedRevision+1||
     !Number.isSafeInteger(result.currentRevision)||result.currentRevision<result.appliedRevision){
   $('local-deny-result').textContent='Исход не подтверждён. UUID: '+unknown.requestId+
    '. Отсутствие записи не доказывает отсутствие эффекта. Не повторяйте; требуется проверка владельцем.';
   return;
  }
  localDenyUnknown=null;localDenyRow=null;localDenyEnabled=false;
  displayProviderInventory();
  $('local-deny-result').textContent='Найдена локальная запись исходного UUID: '+unknown.requestId+
   '. Обновите инвентаризацию. Это не доказательство защиты всех процессов.';
 }catch(error){
  if(sameLocalDenySession(epoch,session))$('local-deny-result').textContent='Проверка не завершена. UUID: '+unknown.requestId+
   '. Не повторяйте применение.';
  throw error;
 }finally{localDenyBusy=false;updateLocalDenyControls();}
}
$('local-deny-target').addEventListener('input',()=>{
 localDenyEpoch++;localDenyPrepared=null;
 if(!localDenyUnknown)$('local-deny-result').textContent='Target изменён. Подготовьте новый запрос.';
 updateLocalDenyControls();
});
$('local-deny-prepare').onclick=action(prepareLocalDeny);
$('local-deny-confirm').onclick=action(confirmLocalDeny);
$('local-deny-readback').onclick=action(readbackLocalDeny);

let selectedProviderFilter='';
function providerFilterOptions(inventory){
 const counts=new Map();
 for(const provider of inventory.providers)counts.set(provider.provider,0);
 for(const row of inventory.operations)counts.set(row.provider,(counts.get(row.provider)??0)+1);
 return [...counts.entries()].sort((a,b)=>a[0].localeCompare(b[0]));
}
function syncProviderFilter(){
 const select=$('providers-select'),previous=select.value??'';
 const options=providerFilterOptions(providerInventory);
 const all=document.createElement('option');all.value='';
 all.textContent='Все провайдеры ('+providerInventory.operations.length+')';
 select.replaceChildren(all);
 for(const [provider,count] of options){
  const option=document.createElement('option');option.value=provider;
  option.textContent=provider+' ('+count+')';select.append(option);
 }
 select.value=options.some(([provider])=>provider===previous)?previous:'';
 selectedProviderFilter=select.value;
}
function visibleProviderRows(inventory,provider,query){
 const search=query.trim().toLowerCase();
 return inventory.operations.filter(row=>(!provider||row.provider===provider)&&[
  row.provider,row.operation,row.actor,row.target,row.configuredPolicy,row.effectivePolicy
 ].some(value=>String(value??'').toLowerCase().includes(search)));
}
function resetProviderSelections(){
 if(localDenyBusy||policyReviewBusy||localDenyUnknown||unifiedBusy||unifiedUnknown)return false;
 unifiedEpoch++;unifiedRow=null;unifiedPrepared=null;
 $('policy-editor-selection').textContent='Выберите правило.';
 $('policy-editor-result').textContent='';
 updateUnifiedControls();
 policyPreviewRow=null;
 $('policy-preview-selection').textContent='Правило не выбрано.';
 $('policy-preview-value').disabled=true;
 $('policy-preview-button').disabled=true;
 $('policy-preview-output').textContent='Выберите правило для предпросмотра.';
 clearPolicyReview();
 localDenyEpoch++;localDenyRow=null;localDenyPrepared=null;
 $('local-deny-selection').textContent='Выберите доступное правило.';
 $('local-deny-target').value='';
 $('local-deny-result').textContent='';
 updateLocalDenyControls();
 return true;
}
function inventoryPolicyText(row){
 const value=row.currentPolicy&&row.scope==='actor'?row.currentPolicy:row.configuredPolicy;
 if(value==='CONDITIONAL')return 'CONDITIONAL · дополнительные условия';
 if(value==='ASK')return 'ASK · согласование владельца';
 if(value==='DENY')return 'DENY · запрещено';
 if(value==='ALLOW')return 'ALLOW · базовое разрешение';
 return String(value??'UNKNOWN');
}
function inventoryReadOnlyReason(row){
 if(row.configuredPolicy==='CONDITIONAL')
  return 'Условия проверяет код операции. Здесь нельзя превратить их в безусловный ALLOW.';
 if(!row.active)return 'Провайдер неактивен.';
 if(row.scope!=='actor'&&row.scope!=='exact')return 'Для этого типа правила нет редактора.';
 if(!Array.isArray(row.editablePolicies)||!row.editablePolicies.length)
  return 'Сервер не допускает изменение этого правила.';
 if(row.editablePolicies.length===1)return 'Других разрешённых значений нет.';
 return 'Изменение этого правила недоступно.';
}
function renderUnifiedProviderCards(target,rows){
 const groups=new Map();
 for(const row of rows){
  if(!groups.has(row.provider))groups.set(row.provider,[]);
  groups.get(row.provider).push(row);
 }
 for(const [provider,items] of groups){
  const section=document.createElement('section');section.className='provider-group';
  const heading=document.createElement('h4');heading.textContent=provider+' · '+items.length;
  section.append(heading);
  const list=document.createElement('div');list.className='provider-rule-list';
  for(const row of items){
   const eligible=canSelectUnified(row),selected=unifiedRow===row;
   const label=document.createElement('label');
   label.className='provider-rule'+(eligible?' can-edit':'')+(selected?' selected':'');
   const input=document.createElement('input');input.type='radio';input.name='selected-policy-operation';
   input.disabled=!eligible;input.checked=selected;
   if(eligible)input.onchange=()=>chooseUnified(row);
   const info=document.createElement('span');info.className='provider-rule-info';
   const name=document.createElement('strong');name.textContent=row.operation;info.append(name);
   const scope=document.createElement('small');
   scope.textContent=(row.actor?'Actor: '+row.actor:'Общее правило')+
    (row.target?' · Target: '+row.target:' · Все target');
   info.append(scope);
   const policy=document.createElement('span');policy.className='provider-rule-policy';
   policy.textContent=inventoryPolicyText(row);info.append(policy);
   const hint=document.createElement('small');hint.className='provider-rule-hint';
   hint.textContent=eligible?'Можно выбрать для изменения':inventoryReadOnlyReason(row);
   info.append(hint);
   label.append(input,info);list.append(label);
  }
  section.append(list);target.append(section);
 }
}
function displayProviderInventory(){
 const target=$('providers-results');target.replaceChildren();
 if(!providerInventory)return;
 const provider=$('providers-select').value??'';
 const matching=visibleProviderRows(providerInventory,provider,$('providers-filter').value??'');
 const total=providerInventory.operations.filter(row=>!provider||row.provider===provider).length;
 const rows=unifiedEnabled&&$('providers-editable-only').checked?
  matching.filter(canSelectUnified):matching;
 $('providers-summary').textContent=rows.length+' из '+total+' правил · '+
  (provider||providerInventory.providers.length+' провайдеров')+
  (unifiedEnabled?' · редактор V2':' · инвентаризация');
 if(!rows.length){
  const empty=document.createElement('p');empty.textContent=
   unifiedEnabled&&$('providers-editable-only').checked?
   'Нет изменяемых правил. Снимите флажок «Только изменяемые», чтобы увидеть все операции.':
   'Нет правил по выбранному фильтру.';
  target.append(empty);return;
 }
 if(unifiedEnabled){renderUnifiedProviderCards(target,rows);return;}
 const table=document.createElement('table');
 const head=document.createElement('thead');const tr=document.createElement('tr');
 for(const label of ['Провайдер','Метод / версия','Тип','Actor / target','Настроено','Действующая политика','Готовность','Действия']){
  const th=document.createElement('th');th.textContent=label;tr.append(th);
 }
 head.append(tr);table.append(head);
 const body=document.createElement('tbody');
 for(const row of rows){
  const cells=[row.provider+' ('+row.providerType+')',row.operation+' · '+(row.version??'неизвестна'),
   row.kind,(row.scope==='unconfigured'?'не назначен':(row.actor??'все'))+' / '+(row.target??'все'),
   row.configuredPolicy,(row.currentPolicy&&row.scope==='actor'?row.currentPolicy+' · с точечными исключениями':row.effectivePolicy==='UNKNOWN'&&['actor','global'].includes(row.scope)&&['DENY','ASK','ALLOW'].includes(row.configuredPolicy)?'Зависит от target':row.effectivePolicy),
   (row.active?'active':'inactive')+' / '+row.credentialStatus+' / upstream '+row.upstreamStatus];
  const tr=document.createElement('tr');
  for(const value of cells){const td=document.createElement('td');td.textContent=value;tr.append(td);}
  const cell=document.createElement('td');
  if(!unifiedEnabled&&row.scope==='exact'&&row.configured&&row.active&&
     ['DENY','ASK','ALLOW'].includes(row.configuredPolicy)&&
     ['DENY','ASK','ALLOW'].includes(row.effectivePolicy)){
   const button=document.createElement('button');button.type='button';button.textContent='Предпросмотр';
   button.onclick=()=>{
    if(localDenyBusy||policyReviewBusy||localDenyUnknown)return;
    policyPreviewRow=row;
    $('policy-preview-selection').textContent=[row.provider,row.operation,row.actor,row.target].join(' · ');
    $('policy-preview-value').value=row.configuredPolicy;
    $('policy-preview-value').disabled=false;
    $('policy-preview-button').disabled=false;
    $('policy-preview-output').textContent='Можно запросить только предпросмотр. Сохранение недоступно.';
    clearPolicyReview();
   };
   cell.append(button);
  }
  if(canSelectUnified(row)){
   const button=document.createElement('button');button.type='button';button.textContent='Изменить политику';
   button.disabled=unifiedBusy||!!unifiedUnknown;button.onclick=()=>chooseUnified(row);cell.append(button);
  }else if(canSelectLocalDeny(row)){
   const button=document.createElement('button');button.type='button';
   button.textContent='Точечный DENY';button.disabled=localDenyBusy||!!localDenyUnknown;
   button.onclick=()=>selectLocalDeny(row);cell.append(button);
  }
  tr.append(cell);
  body.append(tr);
 }
 table.append(body);target.append(table);
}
async function loadProviderInventory(){
 if(localDenyBusy||policyReviewBusy||unifiedBusy)return;
 resetLocalDenyPanel();resetUnifiedPolicyPanel();
 const session=csrf,epoch=localDenyEpoch;
 const inventory=await api('/v1/owner/provider-inventory');
 if(!session||csrf!==session||tab!=='providers'||epoch!==localDenyEpoch)return;
 providerInventory=inventory;
 syncProviderFilter();
 $('policy-preview-panel').hidden=false;
 $('providers-editable-control').hidden=true;
 $('providers-workbench').classList.toggle('unified-workbench',false);
 if(inventory.policyEditorVersion===2){
  const editorCaps=await api(unifiedPrefix+'/capabilities');
  if(!session||csrf!==session||tab!=='providers'||epoch!==localDenyEpoch)return;
  unifiedEnabled=editorCaps.configured===true&&editorCaps.version===2&&editorCaps.ownerOnly===true&&
   editorCaps.requiresFreshStrongWebAuthn===true&&Number.isSafeInteger(inventory.policyRevision)&&
   inventory.policyVersion.endsWith('|owner-policy-v2:'+inventory.policyRevision);
  $('policy-editor-panel').hidden=!unifiedEnabled;
  $('policy-preview-panel').hidden=true;
  $('providers-editable-control').hidden=!unifiedEnabled;
  $('providers-workbench').classList.toggle('unified-workbench',unifiedEnabled);
  if(unifiedUnknown)$('policy-editor-result').textContent='Исход неизвестен. UUID: '+unifiedUnknown.requestId;
  updateUnifiedControls();displayProviderInventory();return;
 }
 policyReviewCapabilities=null;
 try{
  policyReviewCapabilities=await api('/v1/owner/policy/review/capabilities');
 }catch(error){
  if(error.httpStatus!==404)throw error;
 }
 $('policy-review-availability').textContent=policyReviewCapabilities?.configured===true?
  'Доступно только подтверждение просмотра через свежий WebAuthn. Применение прав отключено.':
  'Подтверждение просмотра отключено: защищённый журнал черновиков не подключён.';
 clearPolicyReview();
 policyPreviewRow=null;
 $('policy-preview-selection').textContent='Правило не выбрано.';
 $('policy-preview-value').disabled=true;
 $('policy-preview-button').disabled=true;
 $('policy-preview-output').textContent='Изменения политик не разрешены этим интерфейсом.';
 if(!session||csrf!==session||tab!=='providers'||epoch!==localDenyEpoch)return;
 await loadLocalDenyCapabilities(session,epoch);
 if(csrf===session&&tab==='providers'&&epoch===localDenyEpoch)displayProviderInventory();
}
$('policy-preview-button').onclick=action(async()=>{
 if(!policyPreviewRow||!providerInventory)return;
 const row=policyPreviewRow,inventory=providerInventory,session=csrf;
 clearPolicyReview();
 $('policy-preview-button').disabled=true;
 $('policy-preview-output').textContent='Проверяю текущее правило…';
 try{
  const candidate={
    provider:row.provider,operation:row.operation,actor:row.actor,target:row.target,
    desiredPolicy:$('policy-preview-value').value,
    expectedConfiguredPolicy:row.configuredPolicy,
    expectedPolicyVersion:providerInventory.policyVersion
  };
  const result=await api('/v1/owner/policy/preview',candidate,true);
  if(policyPreviewRow!==row||providerInventory!==inventory||csrf!==session||tab!=='providers')return;
  $('policy-preview-output').textContent=[
   'Правило: '+result.identity.provider+' / '+result.identity.operation,
   'Actor: '+result.identity.actor+' · Target: '+result.identity.target,
   'Сейчас: '+result.current.configuredPolicy+' (эффективно '+result.current.effectivePolicy+')',
   'Предлагается: '+result.proposed.configuredPolicy,
   'Изменение: '+(result.changed?'да':'нет')+' · Риск: '+result.risk,
   'Незавершённые заявки: '+JSON.stringify(result.unresolvedRequests),
   'Для применения понадобятся: '+result.requires.join(', '),
   'Применение: НЕДОСТУПНО. Никакие права не изменены.'
  ].join('\n');
  if(result.changed===true&&result.canApply===false&&policyReviewCapabilities?.configured===true){
   policyPreviewCandidate=candidate;
   $('policy-review-button').disabled=false;
   $('policy-review-output').textContent='После проверки параметров потребуется отдельное касание WebAuthn-ключа. Правило не изменится.';
  }
 }catch(error){
  if(policyPreviewRow!==row||providerInventory!==inventory||csrf!==session||tab!=='providers')return;
  $('policy-preview-output').textContent='Предпросмотр отклонён: '+error.message+'. Обновите инвентаризацию.';
  throw error;
 }finally{if(policyPreviewRow===row&&providerInventory===inventory&&csrf===session&&tab==='providers')$('policy-preview-button').disabled=false;}
});
$('policy-preview-value').addEventListener('change',()=>clearPolicyReview());
$('policy-review-button').onclick=action(async()=>{
 if(!policyPreviewCandidate||policyReviewCapabilities?.configured!==true||policyReviewBusy||localDenyBusy)return;
 const candidate={...policyPreviewCandidate};
 clearPolicyReview('Проверяю точное правило и готовлю одноразовый вызов WebAuthn…');
 policyReviewBusy=true;
 $('policy-preview-value').disabled=true;
 $('policy-preview-button').disabled=true;
 try{
  const begin=await api('/v1/owner/policy/review/begin',{candidate},true);
  if(begin.canApply!==false||begin.policyActivated!==false||begin.kind!=='OWNER_POLICY_DRAFT_REVIEW_ONLY'){
   throw Error('Сервер вернул неожиданную возможность применения. Операция остановлена.');
  }
  $('policy-review-output').textContent='Подтвердите только просмотр этого правила ключом WebAuthn. Изменение прав не произойдёт.';
  const response=await ceremony(begin);
  const result=await api('/v1/owner/policy/review/finish',{
   ceremonyId:begin.ceremonyId,response,change:begin.change
  },true);
  if(result.verified!==true||result.canApply!==false||result.policyActivated!==false||
     result.changeDigest!==begin.changeDigest){
   throw Error('Ответ сервера не подтверждает безопасный просмотр.');
  }
  $('policy-review-output').textContent='WebAuthn-подтверждение просмотра проверено. Права и черновик не изменены.';
 }catch(error){
  $('policy-review-output').textContent='Подтверждение просмотра не завершено: '+error.message+'. Обновите инвентаризацию и выполните новый предпросмотр.';
  throw error;
 }finally{
  policyReviewBusy=false;
  $('policy-preview-value').disabled=!policyPreviewRow;
  $('policy-preview-button').disabled=!policyPreviewRow;
 }
});
$('providers-select').addEventListener('change',()=>{
 // A prepared or unknown mutation always remains bound to its original rule.
 // Never make a hidden selection appear to apply to another provider.
 const select=$('providers-select');
 if(!resetProviderSelections()){select.value=selectedProviderFilter;return;}
 selectedProviderFilter=select.value;displayProviderInventory();
});
$('providers-filter').addEventListener('input',displayProviderInventory);
$('providers-editable-only').addEventListener('change',()=>{
 if(!resetProviderSelections()){$('providers-editable-only').checked=false;return;}
 displayProviderInventory();
});
$('providers-tab').onclick=action(async()=>{switchWorkspaceTab('providers');await loadProviderInventory();});

$('powershell-execute').onclick=action(ownerPowerShellExecute);
$('refresh').onclick=action(async()=>{await refresh();if(tab==='providers')await loadProviderInventory();});
$('notifications').onclick=action(allowNotifications);
setInterval(()=>{if(csrf)refresh();},pollingIntervalMs);
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&csrf)refresh();});
api('/v1/owner/session').then(async data=>{csrf=data.csrf;$('signin').hidden=true;$('workspace').hidden=false;await refresh();}).catch(()=>{});
