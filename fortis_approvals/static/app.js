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
 const controls=document.createElement('div');controls.className='detail-actions';
 const feedback=document.createElement('p');feedback.id='detail-feedback';
 feedback.setAttribute('role','status');feedback.setAttribute('aria-live','polite');
 if(row.state==='PENDING'){
  for(const [decision,title] of [['approve','Подтвердить'],['reject','Отклонить']]){
   const btn=document.createElement('button');btn.type='button';btn.textContent=title;
   if(decision==='approve'&&row.approvalAllowed===false){
    btn.disabled=true;btn.dataset.policyDenied='true';
    btn.title='Подтверждение этой операции отключено';
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

 // Controls first; long payload and preview come after.
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
 tab=which;
 $('approval-view').hidden=which==='powershell';
 $('powershell-view').hidden=which!=='powershell';
 for(const id of ['pending','unresolved','history','powershell']){
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
$('powershell-execute').onclick=action(ownerPowerShellExecute);
$('refresh').onclick=action(refresh);
$('notifications').onclick=action(allowNotifications);
setInterval(()=>{if(csrf)refresh();},pollingIntervalMs);
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&csrf)refresh();});
api('/v1/owner/session').then(async data=>{csrf=data.csrf;$('signin').hidden=true;$('workspace').hidden=false;await refresh();}).catch(()=>{});
