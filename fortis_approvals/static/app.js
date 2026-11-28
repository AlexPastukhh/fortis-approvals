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
 resetRegistryFunctional();resetSemanticRegistry();
 if(message)status(message,true);
}
async function login(){const begin=await api('/v1/login/begin',{});const response=await ceremony(begin);
 const result=await api('/v1/login/finish',{ceremonyId:begin.ceremonyId,response});csrf=result.csrf;
 $('signin').hidden=true;$('registration').hidden=true;$('workspace').hidden=false;status('Вход подтверждён');
 pendingIds=null;await refresh();await loadRegistryFunctional();await loadSemanticRegistry();}
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
 if(row.request.service==='release'&&row.request.operation==='merge_and_register'){
  const p=row.request.params;
  if(/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(p.repository)
     &&Number.isInteger(p.number)&&p.number>0&&p.number<=1000000){
   const pr=document.createElement('a');pr.href='https://github.com/'+p.repository+'/pull/'+p.number;
   pr.target='_blank';pr.rel='noopener noreferrer';pr.textContent=p.repository+' #'+p.number;
   const checks=document.createElement('a');checks.href=pr.href+'/checks';
   checks.target='_blank';checks.rel='noopener noreferrer';checks.textContent='Проверки GitHub';
   const links=document.createElement('p');links.append(pr,document.createTextNode(' · '),checks);
   area.append(links,line('HEAD',p.headSha),line('Base',p.baseSha),
    line('Release Impact',p.classification==='no-deployment'?'Без развёртывания':
     p.targets.map(t=>t.subject.targetId+' · '+t.subject.environment+' · '+t.actions.join(', ')).join('; ')),
    line('Ревизия Registry',p.expectedSourceRevision));
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
 if(row.request.service==='release'&&row.request.operation==='merge_and_register'
    &&['REJECTED','EXPIRED','STALE'].includes(row.state)&&row.failure!=='MERGE_ALREADY_EXTERNAL'){
  const button=document.createElement('button');button.type='button';button.textContent='Предложить снова';
  button.onclick=action(async()=>{
   const next=await api(semanticPrefix+'/repropose',{requestId:row.requestId},true);
   switchWorkspaceTab('pending');await refresh();
   show(await api('/v1/owner/requests/'+next.requestId));
  });
  controls.append(button);
 }
 if(row.mergeRegistrationAvailable===true || row.failure==='MERGE_ALREADY_EXTERNAL'){
  const external=row.failure==='MERGE_ALREADY_EXTERNAL';
  const btn=document.createElement('button');btn.type='button';
  btn.textContent=external?'Зарегистрировать merge из GitHub':'Зарегистрировать подтверждённый merge';
  btn.onclick=action(()=>registerReviewedMerge(row,external));controls.append(btn);
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
async function registerReviewedMerge(row,external){
 if(decisionBusy)return;
 decisionBusy=true;lockDetailActions(true);
 try{
  const path=semanticPrefix+(external?'/register-external':'/register-confirmed');
  const begin=await api(path+'/begin',{requestId:row.requestId},true);
  let result=begin;
  if(!begin.state){
   detailFeedback('Регистрация в Registry · '+begin.mergeSha+' · подтвердите ключом безопасности.');
   const response=await ceremony(begin);
   result=await api(path+'/finish',{requestId:row.requestId,fingerprint:begin.fingerprint,
    ceremonyId:begin.ceremonyId,response},true);
  }
  show(await api('/v1/owner/requests/'+row.requestId));
  const registered=['EXECUTED','EXTERNAL_REGISTERED'].includes(result.state);
  detailFeedback(registered?'Merge зарегистрирован в Registry.':
   'Исход записи требует проверки.',!registered);
 }finally{decisionBusy=false;lockDetailActions(false);await refresh();}
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
 $('approval-view').hidden=['powershell','providers','semantic-registry'].includes(which);
 $('semantic-registry-view').hidden=which!=='semantic-registry';
 $('powershell-view').hidden=which!=='powershell';
 $('providers-view').hidden=which!=='providers';
 for(const id of ['pending','unresolved','history','powershell','providers','semantic-registry']){
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
async function refreshConfirmedUnified(message,session){
 // Never render stale policies after a confirmed write. The fresh inventory
 // comes only from the authenticated owner GET, with no additional mutation.
 providerInventory=null;
 $('providers-results').replaceChildren();
 $('providers-summary').textContent='Изменение записано. Обновляю инвентаризацию…';
 try{
  await loadProviderInventory();
  if(csrf===session&&tab==='providers'&&unifiedEnabled)
   $('policy-editor-result').textContent=message;
 }catch(_error){
  $('providers-summary').textContent='Изменение записано, но инвентаризация не обновлена. Нажмите «Обновить».';
 }
}
async function confirmUnified(){
 const prepared=unifiedPrepared;
 if(!prepared||unifiedBusy||unifiedUnknown||!unifiedSame(prepared.epoch,prepared.session))return;
 const {begin,epoch,session}=prepared;
 unifiedPrepared=null;unifiedBusy=true;updateUnifiedControls();
 let sent=false,committedMessage='';
 try{
  const response=await ceremony(begin);
  if(!unifiedSame(epoch,session))return;
  unifiedUnknown=begin.change;sent=true;
  const result=await api(unifiedPrefix+'/finish',{ceremonyId:begin.ceremonyId,response,change:begin.change},true);
  if(!unifiedReceiptMatches(result,begin.change))throw Error('Запись не подтверждена.');
  unifiedUnknown=null;unifiedRow=null;
  committedMessage='Изменение подтверждено. UUID: '+result.requestId+
   '. Ревизия: '+result.appliedRevision+'. Инвентаризация обновлена.';
 }catch(err){
  if(unifiedSame(epoch,session))$('policy-editor-result').textContent=sent?
   'Исход неизвестен. UUID: '+begin.change.requestId+'. Используйте проверку UUID, не повторяйте изменение.':
   'WebAuthn не завершён. Изменение не отправлено.';
  throw err;
 }finally{unifiedBusy=false;updateUnifiedControls();}
 if(committedMessage&&csrf===session&&tab==='providers')
  await refreshConfirmedUnified(committedMessage,session);
}
async function readbackUnified(){
 if(!unifiedUnknown||unifiedBusy||!unifiedEnabled||!csrf||tab!=='providers')return;
 const change=unifiedUnknown,epoch=unifiedEpoch,session=csrf;
 unifiedBusy=true;updateUnifiedControls();
 let confirmedMessage='';
 try{
  const result=await api(unifiedPrefix+'/readback',{requestId:change.requestId},true);
  if(!unifiedSame(epoch,session))return;
  if(!unifiedReceiptMatches(result,change)){
   $('policy-editor-result').textContent='Исход не подтверждён. Не повторяйте изменение. UUID: '+change.requestId;return;
  }
  unifiedUnknown=null;unifiedRow=null;
  confirmedMessage='Запись исходного UUID подтверждена. Инвентаризация обновлена.';
  $('policy-editor-result').textContent=confirmedMessage;
 }finally{unifiedBusy=false;updateUnifiedControls();}
 if(confirmedMessage&&csrf===session&&tab==='providers')
  await refreshConfirmedUnified(confirmedMessage,session);
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

let selectedProviderFilter='',selectedPolicyFilter='';
function isCompositeRow(row){return row.operationKind==='composite'||(row.provider==='registry'&&['begin_release_group','report_release_results'].includes(row.operation))||(row.provider==='release'&&row.operation==='merge_and_register');}
function providerCategory(row){return isCompositeRow(row)?'@composite':row.provider;}
function providerFilterOptions(inventory){
 const counts=new Map();
 for(const provider of inventory.providers)counts.set(provider.provider,0);
 for(const row of inventory.operations)counts.set(providerCategory(row),(counts.get(providerCategory(row))??0)+1);
 return [...counts.entries()].sort((a,b)=>a[0].localeCompare(b[0]));
}
function syncProviderFilter(){
 const select=$('providers-select'),previous=select.value??'';
 const options=providerFilterOptions(providerInventory);
 const all=document.createElement('option');all.value='';
 all.textContent='Все категории ('+providerInventory.operations.length+')';
 select.replaceChildren(all);
 for(const [provider,count] of options){
  const option=document.createElement('option');option.value=provider;
  option.textContent=(provider==='@composite'?'Composite Actions':provider)+' ('+count+')';select.append(option);
 }
 select.value=options.some(([provider])=>provider===previous)?previous:'';
 selectedProviderFilter=select.value;
}
function visibleProviderRows(inventory,provider,query,policy=''){
 const search=query.trim().toLowerCase();
 return inventory.operations.filter(row=>(!provider||providerCategory(row)===provider)&&
  (!policy||(row.currentPolicy??row.configuredPolicy??'UNKNOWN')===policy)&&[
  row.provider,row.operation,row.actor,row.target,row.currentPolicy??row.configuredPolicy,row.effectivePolicy
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
 const value=row.currentPolicy??row.configuredPolicy;
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
   if(row.operationKind==='composite'){
    const children=document.createElement('small');children.textContent=(row.children??[]).map(c=>c.service+'.'+c.operation+' v'+c.version).join(' → ')+(row.protectedOwnerGate?' · обязательное ASK':'');info.append(children);
   }

   if(row.operationKind==='context-child'){
    const context=document.createElement('small');
    context.textContent='Дочерняя операция Composite: '+(row.contextParents??[]).map(p=>p.service+'.'+p.operation).join(', ');
    info.append(context);
   }
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
 const policy=$('providers-policy').value??'';
 const matching=visibleProviderRows(providerInventory,provider,$('providers-filter').value??'',policy);
 const total=providerInventory.operations.filter(row=>!provider||providerCategory(row)===provider).length;
 // Capability controls WRITE permissions, not the presentation of a V2
 // inventory. Never switch to the legacy table during a capability refresh.
 const v2Inventory=providerInventory.policyEditorVersion===2;
 const rows=v2Inventory&&unifiedEnabled&&$('providers-editable-only').checked?
  matching.filter(canSelectUnified):matching;
 $('providers-summary').textContent=rows.length+' из '+total+' правил · '+
  (provider==='@composite'?'Composite Actions':provider||providerInventory.providers.length+' провайдеров')+
  (policy?' · '+policy:'')+(v2Inventory?' · редактор V2':' · инвентаризация');
 if(!rows.length){
  const empty=document.createElement('p');empty.textContent=
   v2Inventory&&unifiedEnabled&&$('providers-editable-only').checked?
   'Нет изменяемых правил. Снимите флажок «Только изменяемые», чтобы увидеть все операции.':
   'Нет правил по выбранному фильтру.';
  target.append(empty);return;
 }
 if(v2Inventory){renderUnifiedProviderCards(target,rows);return;}
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
$('providers-policy').addEventListener('change',()=>{
 const select=$('providers-policy');
 if(!resetProviderSelections()){select.value=selectedPolicyFilter;return;}
 selectedPolicyFilter=select.value;displayProviderInventory();
});
$('providers-filter').addEventListener('input',displayProviderInventory);
$('providers-editable-only').addEventListener('change',()=>{
 if(!resetProviderSelections()){$('providers-editable-only').checked=false;return;}
 displayProviderInventory();
});
$('providers-tab').onclick=action(async()=>{switchWorkspaceTab('providers');await loadProviderInventory();});

$('powershell-execute').onclick=action(ownerPowerShellExecute);
$('refresh').onclick=action(async()=>{await refresh();if(tab==='providers')await loadProviderInventory();await loadSemanticRegistry();if(tab==='semantic-registry')await semanticList();});
$('notifications').onclick=action(allowNotifications);
setInterval(()=>{if(csrf)refresh();},pollingIntervalMs);
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&csrf)refresh();});
let registryCapability=null,registryBusy=false;
function resetRegistryFunctional(){
 registryCapability=null;
 $('registry-functional-panel').hidden=true;
 for(const name of ['pr-number','pr-head','review-id','evidence-id','evidence-digest','revision','ingest-id'])
  $('registry-'+name).value='';
 $('registry-functional-result').textContent='';
}
async function loadRegistryFunctional(){
 const session=csrf;
 if(!session)return;
 try{
  const value=await api('/v1/owner/registry/capabilities');
  if(csrf!==session)return;
  if(value.configured!==true||value.admissionAllowed!==false||value.deploymentAllowed!==false){
   resetRegistryFunctional();return;
  }
  registryCapability=value;
  $('registry-revision').value=String(value.localRevision);
  $('registry-functional-panel').hidden=false;
 }catch(error){
  // Unsupported legacy portal or temporarily unavailable Registry. Do not
  // break the main approval queue or imply successful Registry activation.
  if(csrf===session){registryCapability=null;$('registry-functional-panel').hidden=true;}
 }
}
function registryId(id){
 const field=$(id);
 if(!field.value)field.value=crypto.randomUUID();
 return field.value;
}
async function registryAction(kind){
 if(registryBusy||!registryCapability||!csrf)return;
 const session=csrf;
 registryBusy=true;
 const buttons=['registry-review','registry-retain','registry-ingest','registry-refresh'].map($);
 for(const button of buttons)button.disabled=true;
 try{
  let body;
  if(kind==='review')body={requestId:registryId('registry-review-id'),
   number:Number($('registry-pr-number').value),headSha:$('registry-pr-head').value};
  else if(kind==='retain')body={requestId:$('registry-review-id').value};
  else body={repository:registryCapability.repository,operationId:registryId('registry-ingest-id'),
   evidenceId:$('registry-evidence-id').value,evidenceDigest:$('registry-evidence-digest').value,
   expectedRevision:Number($('registry-revision').value)};
  const result=await api('/v1/owner/registry/'+kind,body,true);
  if(csrf!==session)return;
  $('registry-functional-result').textContent=JSON.stringify(result,null,2);
  if(kind==='retain'){
   $('registry-evidence-id').value=result.evidenceId;
   $('registry-evidence-digest').value=result.evidenceDigest;
  }
  await refresh();
 }catch(error){
  if(csrf===session)$('registry-functional-result').textContent=
   'Остановлено: '+error.message+'. Сохраните UUID и проверьте исходную заявку; не создавайте новый UUID при неизвестном результате.';
 }finally{registryBusy=false;for(const button of buttons)button.disabled=false;}
}
for(const kind of ['review','retain','ingest'])
 $('registry-'+kind).onclick=action(()=>registryAction(kind));
$('registry-refresh').onclick=action(loadRegistryFunctional);
// Live semantic panel: no mock data, no calculated deployment status.
const semanticPrefix='/v1/owner/registry/semantic';
let semanticCaps=null,semanticRows=[],semanticSelected=new Map(),semanticBusy=false,semanticEpoch=0;
let semanticCursor=null,semanticView='list_components',semanticUnknown=null,semanticCatalog=null;
const semanticPendingReads=new Map();
function resetSemanticRegistry(){
 semanticEpoch++;semanticCaps=null;semanticRows=[];semanticSelected.clear();semanticCursor=null;semanticPendingReads.clear();
 $('semantic-registry-tab').hidden=true;$('semantic-registry-rows').replaceChildren();
 $('semantic-registry-result').textContent='';$('semantic-report-form').hidden=true;
 $('semantic-discovery-status').replaceChildren();$('semantic-discovery-status').hidden=true;
 semanticControls();
}
function semanticControls(){
 const ready=!!semanticCaps&&!semanticBusy&&!semanticUnknown&&semanticSelected.size>0;
 const rows=[...semanticSelected.values()];
 $('semantic-plan').disabled=!ready||rows.some(r=>!r.desired);
 $('semantic-begin').disabled=!ready||rows.some(r=>!r.desired||r.activeAttempt||r.incidentStatus);
 $('semantic-report').disabled=!ready||rows.some(r=>r.incidentStatus);
 $('semantic-readback').hidden=!semanticUnknown;
 $('semantic-next').hidden=!semanticCursor;$('semantic-next').disabled=semanticBusy;
}
function semanticRequest(operation,params,service='registry'){
 return {requestId:crypto.randomUUID(),service,operation,target:semanticCaps.target,params,reason:'Owner Portal'};
}
function showDiscoveryStatus(rows,repository){
 const box=$('semantic-discovery-status');box.replaceChildren();box.hidden=true;
 if(!Array.isArray(rows)||!/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(repository))return;
 const labels={CI_NOT_READY:'CI не подтверждён',DRAFT:'Черновик',BASE_NOT_MAIN:'Целевая ветка не main',
  BASE_CHANGED:'Изменён base',DIFF_UNVERIFIED:'Diff не подтверждён',IMPACT_INVALID:'Release Impact не подтверждён',
  DEPENDENCY_UNVERIFIED:'Зависимости не подтверждены',REVIEW_CHANGED:'Данные изменились после проверки',
  PROPOSAL_UNAVAILABLE:'Создание заявки недоступно',
  EXTERNAL_MERGE:'Слито в GitHub. Запись в Registry требует отдельной проверки'};
 for(const row of rows){
  if(row.state!=='BLOCKED'||!Number.isInteger(row.number)||row.number<1||row.number>1000000)continue;
  const line=document.createElement('p'),link=document.createElement('a');
  link.href='https://github.com/'+repository+'/pull/'+row.number;link.target='_blank';link.rel='noopener noreferrer';
  link.textContent='PR #'+row.number;line.append(link,document.createTextNode(' — '+(labels[row.reason]??'Предложение заблокировано')));
  box.append(line);
 }
 box.hidden=!box.childElementCount;
}
async function loadSemanticRegistry(){
 if(!csrf)return;
 const session=csrf,epoch=++semanticEpoch;
 try{
  const caps=await api(semanticPrefix+'/capabilities');
  if(csrf!==session||epoch!==semanticEpoch)return;
  if(caps.configured!==true){resetSemanticRegistry();return;}
  semanticCaps=caps;$('semantic-registry-tab').hidden=false;
  if(caps.discoveryConfigured){
   $('semantic-discovery-status').replaceChildren();$('semantic-discovery-status').hidden=true;
   try{const rows=await api(semanticPrefix+'/discover',{},true);
    if(csrf!==session||epoch!==semanticEpoch)return;
    showDiscoveryStatus(rows,caps.repository);await refresh();}
   catch(err){if(csrf===session&&epoch===semanticEpoch){
    const box=$('semantic-discovery-status');box.textContent='Обнаружение PR недоступно: '+err.message;box.hidden=false;
   }}
  }
 }catch(err){if(csrf===session&&epoch===semanticEpoch)resetSemanticRegistry();}
}
function semanticText(parent,tag,text){const node=document.createElement(tag);node.textContent=String(text??'UNKNOWN');parent.append(node);return node;}
function semanticDate(value){
 return Number.isSafeInteger(value)?new Date(value*1000).toLocaleString():'Время неизвестно';
}
function semanticMaintenance(parent,profile,digest){
 const details=document.createElement('details');parent.append(details);
 semanticText(details,'summary','Профиль паузы');
 if(!profile){
  semanticText(details,'p','Ограничения не подтверждены.');
  return;
 }
 details.append(line('Окно релиза',profile.beginRequired?'Обязательно':'Не требуется'));
 details.append(line('Заморозка состояния',profile.stateFreeze?'Требуется':'Не требуется'));
 const ops=profile.blockedOperations.map(op=>op.service+'.'+op.operation);
 details.append(line('Явные блокировки',ops.length?ops.join(', '):'Нет'));
 for(const note of profile.notes)semanticText(details,'p',note);
 if(/^[0-9a-f]{64}$/.test(digest??''))details.append(line('Версия ограничений',digest));
}
function semanticRender(){
 const box=$('semantic-registry-rows');box.replaceChildren();semanticSelected.clear();
 const table=document.createElement('table');table.className='semantic-table';box.append(table);
 const head=table.createTHead().insertRow();
 for(const h of ['Выбор','Компонент','Installed','Desired','Owner Reported','Состояние','Действия'])semanticText(head,'th',h);
 const filter=$('semantic-filter').value;
 const rows=semanticView==='list_active_releases'?semanticRows:semanticRows.filter(row=>{
  const unknown=['UNKNOWN','PLANNED_UNVERIFIED'].includes(row.planningState);
  return filter==='all'||(filter==='unknown'?unknown:!unknown&&row.planningState!=='DEPLOYED');
 });
 for(const row of rows){
  const tr=table.insertRow(),cell=tr.insertCell(),check=document.createElement('input');check.type='checkbox';
  check.disabled=!row.deployable;cell.append(check);
  const k=JSON.stringify(row.subject);check.onchange=()=>{if(check.checked)semanticSelected.set(k,row);else semanticSelected.delete(k);semanticControls();};
  const link=document.createElement('button');link.type='button';link.textContent=row.subject.targetId+' · '+row.subject.environment;
  const component=tr.insertCell();component.append(link);link.onclick=action(()=>semanticHistory(row));
  semanticMaintenance(component,row.maintenanceProfile,row.restrictionDigest);
  const installed=semanticText(tr,'td',row.installed?row.installed.source.sourceSha:'UNKNOWN');
  if(row.installed)semanticText(installed,'p',row.installed.validity+' · '+semanticDate(row.installed.observedAt));
  const desired=semanticText(tr,'td',row.desired?.source?.sourceSha??'UNKNOWN');
  const pr=row.desired?.pullRequest;
  if(pr?.repository===row.subject.repository&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(pr.repository)
     &&Number.isInteger(pr.number)&&pr.number>0&&pr.number<=1000000){
   const source=semanticText(desired,'p',row.desired.evidenceVerified?'Подтверждённый merge ':'Переход на новую версию ');
   const prLink=semanticText(source,'a','PR #'+pr.number);
   prLink.href='https://github.com/'+pr.repository+'/pull/'+pr.number;
   prLink.target='_blank';prLink.rel='noopener noreferrer';
  }
  const reported=semanticText(tr,'td',row.ownerReported?.outcome??'UNKNOWN');
  if(row.ownerReported)semanticText(reported,'p',row.ownerReported.actor+' · '+semanticDate(row.ownerReported.observedAt));
  const planning={QUEUED:'Ожидает релиза',DEPLOYED:'Установлен',IN_PROGRESS:'Релиз идёт',
   FAILED:'Ошибка релиза',PLANNED_UNVERIFIED:'Источник требует проверки',UNKNOWN:'Неизвестно'};
  semanticText(tr,'td',(planning[row.planningState]??'Неизвестно')+(row.activeAttempt?' · активное окно':''));
  semanticText(tr,'td',(row.outstandingActions??[]).join(', ')||'—');
 }
 semanticControls();
}
async function semanticRead(operation,params){
 const key=JSON.stringify([operation,params,semanticCaps.target]);
 const q=semanticPendingReads.get(key)??semanticRequest(operation,params),session=csrf;
 const response=await api(semanticPrefix+'/read',q,true);
 if(csrf!==session)throw Error('Сессия изменена');
 if(response.state){
  if(response.state==='PENDING'||response.state==='APPROVED')semanticPendingReads.set(key,q);
  else semanticPendingReads.delete(key);
  $('semantic-registry-result').textContent=response.state+' · '+q.requestId+' · подтверждение через очередь; повторите исходный READ после одобрения.';
  throw Error('READ не выполнен: '+response.state+'; данные не получены.');}
 semanticPendingReads.delete(key);
 return response.data;
}
async function semanticList(append=false){
 if(!semanticCaps||semanticBusy)return;
 const session=csrf,epoch=++semanticEpoch;semanticBusy=true;semanticControls();
 if(!append){semanticRows=[];semanticCursor=null;semanticSelected.clear();$('semantic-registry-rows').replaceChildren();}
 try{
  const data=await semanticRead(semanticView,{repository:semanticCaps.repository,page:{limit:20,cursor:append?semanticCursor:null}});
  if(csrf!==session||epoch!==semanticEpoch)return;
  semanticRows.push(...data.data.items);semanticCursor=data.data.nextCursor;semanticCatalog=data.catalogSha256;
  $('semantic-registry-status').textContent='Ревизия '+data.snapshotRevision+' · '+(data.runtimeAdmissionAllowed?'':'локальная проекция, допуск не подтверждён');
  semanticRender();
 }catch(err){if(csrf===session&&epoch===semanticEpoch){semanticRows=[];semanticSelected.clear();semanticCursor=null;
  $('semantic-registry-rows').replaceChildren();$('semantic-registry-status').textContent=err.message+' · состояние неизвестно';}}
 finally{semanticBusy=false;semanticControls();}
}
async function semanticHistory(row){
 $('semantic-registry-result').textContent='';
 const data=await semanticRead('list_history',{subject:row.subject,page:{limit:20,cursor:null}});
 const box=$('semantic-registry-result');
 for(const row of data.data.items){
  const event=row.event,receipt=row.receipt;
  const description=event.number?'PR #'+event.number+' · '+event.sourceSha:
   [event.kind,event.params?.outcome,event.actor].filter(Boolean).join(' · ');
  box.append(line(semanticDate(event.params?.observedAt??receipt.recordedAt),description));
  if(event.params?.evidenceDigests?.length)box.append(line('Свидетельства',event.params.evidenceDigests.join(', ')));
 }
 if(!data.data.items.length)box.textContent='Записей пока нет.';
 if(!data.data.complete)box.append(line('История','Показаны первые '+data.data.items.length+' записей'));
}
function semanticItems(){
 return [...semanticSelected.values()].sort((a,b)=>{
 const x=[a.subject.repository.toLowerCase(),a.subject.targetId,a.subject.environment].join('\0');
 const y=[b.subject.repository.toLowerCase(),b.subject.targetId,b.subject.environment].join('\0');return x<y?-1:x>y?1:0;});
}
function semanticGuard(row){return {subject:row.subject,source:row.desired?.source??null,
 expected:{targetRevision:row.targetRevision,desiredRecordId:row.desired?.recordId??null,catalogSha256:semanticCatalog}};}
function semanticActualSource(){
 if($('semantic-source-unknown').checked){
  if(!['initial','external'].includes($('semantic-context').value)||$('semantic-outcome').value!=='UNKNOWN')throw Error('Неизвестный источник допустим только для initial/external и UNKNOWN.');
  return null;
 }
 const source={sourceSha:$('semantic-source-sha').value.trim(),catalogCommitSha:$('semantic-catalog-commit').value.trim(),
 catalogSha256:$('semantic-catalog-sha').value.trim(),artifactSha256:$('semantic-artifact-sha').value.trim()||null};
 if(!/^[a-f0-9]{40}$/.test(source.sourceSha)||!/^[a-f0-9]{40}$/.test(source.catalogCommitSha)||!/^[a-f0-9]{64}$/.test(source.catalogSha256)||
 (source.artifactSha256!==null&&!/^[a-f0-9]{64}$/.test(source.artifactSha256)))throw Error('Укажите точные фактические SHA.');
 return source;
}
async function semanticPlan(){
 $('semantic-registry-result').textContent='';
 const data=await semanticRead('plan_batch',{items:semanticItems().map(r=>({subject:r.subject,source:r.desired.source}))});
 const plan=data.data,box=$('semantic-registry-result');
 const status={PLAN_READY:'План рассчитан',STALE:'Исходники изменились',BLOCKED:'Есть ограничения',UNKNOWN:'Не хватает подтверждений'};
 semanticText(box,'h3',status[plan.status]??plan.status);
 if(plan.order.length)box.append(line('Порядок релиза',plan.order.map(s=>s.targetId+' · '+s.environment).join(' → ')));
 for(const target of plan.targets){
  semanticText(box,'h4',target.subject.targetId+' · '+target.subject.environment);
  if(target.outstandingActions.length)box.append(line('Действия',target.outstandingActions.join(', ')));
  const procedure=semanticText(box,'p','Процедура ');
  if(/^docs\/[A-Za-z0-9_./-]+\.md(?:#[a-z0-9-]+)?$/.test(target.procedure)
     &&!target.procedure.split('/').includes('..')&&/^[a-f0-9]{40}$/.test(target.source.sourceSha)){
   const link=semanticText(procedure,'a',target.procedure);
   link.href='https://github.com/'+target.subject.repository+'/blob/'+target.source.sourceSha+'/'+target.procedure;
   link.target='_blank';link.rel='noopener noreferrer';
  }else procedure.append(document.createTextNode(target.procedure));
  box.append(line('Проверки',target.verification.join(', ')));
  semanticMaintenance(box,target.maintenance,target.restrictionDigest);
 }
 for(const group of plan.buildGroups)
  box.append(line('Сборка',group.identity.buildUnitId+' · '+group.artifactState+' · '+
   group.subjects.map(s=>s.targetId).join(', ')));
 for(const conflict of plan.windowConflicts)
  box.append(line('Раздельные окна',conflict.subjects.map(s=>s.targetId).join(', ')));
 for(const check of plan.checks){
  if(!['PASS','NOT_APPLICABLE'].includes(check.status))
   box.append(line(check.subject?.targetId??'Проверка',check.code+' · '+check.status));
 }
}
async function semanticSubmit(report){
 if(semanticBusy||semanticUnknown)return;
 const context=$('semantic-context').value;
 const time=report?$('semantic-observed-at').value:'';
 const observedAt=time?Math.floor(new Date(time).getTime()/1000):null;
 const evidenceDigests=report?[...new Set($('semantic-evidence').value.trim().split(/[\s,]+/).filter(Boolean))].sort():[];
 if((time&&(!Number.isSafeInteger(observedAt)||observedAt<0))||evidenceDigests.length>16||
    evidenceDigests.some(digest=>!/^[a-f0-9]{64}$/.test(digest)))throw Error('Проверьте время и SHA256 свидетельств.');
 if(report&&context!=='release'&&semanticSelected.size!==1)throw Error('Для фактического внешнего источника выберите один компонент.');
 const items=semanticItems().map(r=>{
  const p=semanticGuard(r);if(!report)return p;
  const source=context==='release'?(r.activeAttempt?.verifiedSource??r.activeAttempt?.source??p.source):semanticActualSource();
  if(context==='release'&&!source)throw Error('Нет точного источника релиза.');
  if(context!=='release'&&r.activeAttempt&&context!=='historical')throw Error('Сначала разберите активное окно.');
  return {...p,source,attemptId:context==='release'?r.activeAttempt?.attemptId??null:null,
   context,outcome:$('semantic-outcome').value,
   assertion:$('semantic-assertion').value,observedAt,evidenceDigests};
 });
 if(!items.length||items.length>20)throw Error('Выберите от 1 до 20 компонентов.');
 if(report&&!$('semantic-assertion').value.trim())throw Error('Укажите результат владельца.');
 const op=report?(items.length===1?'report_release_result':'report_release_results'):(items.length===1?'begin_release':'begin_release_group');
 const q=semanticRequest(op,items.length===1?items[0]:{items});semanticBusy=true;semanticControls();
 try{
  const out=await api(semanticPrefix+'/submit',q,true);
  $('semantic-registry-result').textContent=out.state+' · '+out.requestId;
  if(out.state==='UNCERTAIN'||out.state==='DISPATCHED')semanticUnknown=out.requestId;
  $('semantic-report-form').hidden=true;await refresh();
 }catch(err){semanticUnknown=q.requestId;$('semantic-registry-result').textContent='Не подтверждено: '+q.requestId+' · '+err.message+' · проверьте исходную заявку. Новый UUID не создаётся.';}
 finally{semanticBusy=false;semanticControls();}
 await semanticList();
}
$('semantic-registry-tab').onclick=action(async()=>{switchWorkspaceTab('semantic-registry');await semanticList();});
$('semantic-board').onclick=action(async()=>{semanticView='list_components';await semanticList();});
$('semantic-active').onclick=action(async()=>{semanticView='list_active_releases';await semanticList();});
$('semantic-filter').onchange=()=>semanticRender();
$('semantic-next').onclick=action(()=>semanticList(true));
$('semantic-maintenance').onclick=action(async()=>{
 const box=$('semantic-registry-result');box.replaceChildren();
 const response=await semanticRead('get_maintenance_status',{repository:semanticCaps.repository});
 const status=response.data;
 box.append(line('Состояние',status.status),line('State Freeze',status.stateFreeze===null?'Неизвестно':status.stateFreeze?'Активен':'Нет'));
 for(const op of status.blockedOperations??[])box.append(line('Заблокировано',op.service+'.'+op.operation));
 for(const hold of status.holds??[]){
  semanticText(box,'h4',hold.subject.targetId+' · '+hold.subject.environment);
  for(const note of hold.maintenance.notes)semanticText(box,'p',note);
 }
});
$('semantic-plan').onclick=action(semanticPlan);
$('semantic-begin').onclick=action(()=>semanticSubmit(false));
$('semantic-report').onclick=()=>{$('semantic-report-form').hidden=false;};
$('semantic-context').onchange=()=>{$('semantic-actual-source').hidden=$('semantic-context').value==='release';};
$('semantic-readback').onclick=action(async()=>{
 const ident=semanticUnknown;if(!ident)return;
 const row=await api('/v1/owner/requests/'+ident);
 $('semantic-registry-result').textContent=row.state+' · '+ident;
 if(!['UNCERTAIN','DISPATCHED','APPROVED','PENDING'].includes(row.state)){semanticUnknown=null;await semanticList();}
 semanticControls();
});
$('semantic-report-confirm').onclick=action(()=>semanticSubmit(true));

const paletteTokens=[['primary','Primary · основная кнопка'],['primary-text','Текст Primary'],['accent','Акцент'],['page','Общий фон'],['surface','Карточки и поля'],['text','Основной текст'],['muted','Вторичный текст'],['border','Границы'],['soft','Вторичный фон'],['selection','Выбранная строка'],['selection-border','Граница выбора'],['link','Ссылки'],['ok','Успех'],['warn','Предупреждение'],['bad','Ошибка'],['open-bg','Фон Open'],['closed-bg','Фон Merged'],['closed-text','Текст Merged'],['focus','Фокус клавиатуры']];
const paletteDefaults={light:{'primary':'#356b50','primary-text':'#ffffff','accent':'#355f8b','page':'#f4f6f8','surface':'#fbfcfd','text':'#293442','muted':'#586677','border':'#d9e0e7','soft':'#eef2f6','selection':'#eaf1f8','selection-border':'#8ca9c8','link':'#315d89','ok':'#326849','warn':'#80571e','bad':'#a13d42','open-bg':'#e5eee7','closed-bg':'#ede9f2','closed-text':'#705781','focus':'#3b73a6'},dark:{'primary':'#36694e','primary-text':'#ffffff','accent':'#8aafcf','page':'#171c23','surface':'#1e252e','text':'#d5dde6','muted':'#a3afbf','border':'#37414e','soft':'#272f3a','selection':'#283b4c','selection-border':'#6587a7','link':'#9cbddd','ok':'#9bc5a8','warn':'#dfba80','bad':'#e1a1a1','open-bg':'#293e33','closed-bg':'#382e45','closed-text':'#c8b3db','focus':'#9cbddd'}};
const paletteKey='fortis.owner.palette.v1',media=window.matchMedia('(prefers-color-scheme: dark)');
let palette={light:{...paletteDefaults.light},dark:{...paletteDefaults.dark}},themeChoice='auto';
const validColor=v=>typeof v==='string'&&/^#[0-9a-f]{6}$/i.test(v);
function readPalette(value){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['light','dark'].includes(k)))throw Error('Ожидается объект light/dark');const next={light:{...paletteDefaults.light},dark:{...paletteDefaults.dark}};for(const m of ['light','dark']){const part=value[m];if(!part||typeof part!=='object'||Array.isArray(part))throw Error('Нужны обе темы');for(const [k,v] of Object.entries(part)){if(!Object.hasOwn(paletteDefaults[m],k)||!validColor(v))throw Error('Некорректный токен: '+k);next[m][k]=v.toLowerCase()}}return next;}
function persistPalette(){try{localStorage.setItem(paletteKey,JSON.stringify({theme:themeChoice,palette}));$('palette-storage').textContent='Настройки сохранены локально в браузере.'}catch{$('palette-storage').textContent='Локальное сохранение недоступно. Для переноса используйте экспорт JSON.'}}
function effectiveTheme(){return themeChoice==='auto'?(media.matches?'dark':'light'):themeChoice}
function applyPalette(){const m=effectiveTheme(),root=document.documentElement;root.setAttribute('data-theme',m);for(const [k,v] of Object.entries(palette[m]))root.style.setProperty('--'+k,v);$('palette-mode').value=m;checkPaletteContrast(m)}
function lum(h){const c=h.slice(1).match(/../g).map(x=>parseInt(x,16)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4);return .2126*c[0]+.7152*c[1]+.0722*c[2]}
function contrast(a,b){const x=lum(a),y=lum(b);return (Math.max(x,y)+.05)/(Math.min(x,y)+.05)}
function checkPaletteContrast(m){const p=palette[m],pairs=[['text','surface'],['text','page'],['muted','surface'],['muted','page'],['link','surface'],['ok','surface'],['warn','surface'],['bad','surface'],['primary-text','primary'],['text','selection'],['ok','open-bg'],['closed-text','closed-bg']];const results=pairs.map(([a,b])=>({name:a+' / '+b,ratio:contrast(p[a],p[b])}));const failures=results.filter(x=>x.ratio<4.5);$('palette-contrast').className=failures.length?'warn':'ok';$('palette-contrast').textContent=failures.length?'Низкий контраст текста: '+failures.map(x=>x.name+' '+x.ratio.toFixed(2)+':1').join('; '):'Основные пары текста: контраст не ниже 4.5:1. Это не полная проверка доступности.';}
function drawPaletteFields(){const m=effectiveTheme(),area=$('palette-fields');area.replaceChildren();for(const [k,label] of paletteTokens){const row=document.createElement('label');row.className='palette-item';const title=document.createElement('span');title.textContent=label;const picker=document.createElement('input');picker.type='color';picker.value=palette[m][k];picker.setAttribute('aria-label',label+' — выбор цвета');const hex=document.createElement('input');hex.type='text';hex.value=picker.value;hex.maxLength=7;hex.spellcheck=false;hex.setAttribute('aria-label',label+' — HEX');const update=v=>{if(!validColor(v)){hex.setAttribute('aria-invalid','true');return}hex.removeAttribute('aria-invalid');palette[m][k]=v.toLowerCase();picker.value=palette[m][k];applyPalette();persistPalette()};picker.oninput=()=>{hex.value=picker.value;update(picker.value)};hex.oninput=()=>update(hex.value);row.append(title,picker,hex);area.append(row)}}
function changeTheme(v){themeChoice=v;$('theme').value=v;applyPalette();drawPaletteFields();persistPalette()}
try{const saved=JSON.parse(localStorage.getItem(paletteKey)||'null');if(saved){palette=readPalette(saved.palette);if(['auto','light','dark'].includes(saved.theme))themeChoice=saved.theme}}catch{}
$('theme').onchange=()=>changeTheme($('theme').value);
$('palette-mode').onchange=()=>changeTheme($('palette-mode').value);
$('palette-reset').onclick=()=>{const m=effectiveTheme();palette[m]={...paletteDefaults[m]};applyPalette();drawPaletteFields();persistPalette()};
$('palette-reset-all').onclick=()=>{palette={light:{...paletteDefaults.light},dark:{...paletteDefaults.dark}};applyPalette();drawPaletteFields();persistPalette()};
$('palette-export').onclick=()=>{$('palette-json').value=JSON.stringify(palette,null,2);$('palette-json').select();$('palette-feedback').textContent='JSON готов для копирования.'};
$('palette-import').onclick=()=>{try{const next=readPalette(JSON.parse($('palette-json').value));palette=next;applyPalette();drawPaletteFields();persistPalette();$('palette-feedback').textContent='Палитра импортирована.'}catch(e){$('palette-feedback').textContent='Импорт отклонён: '+e.message}};
if(media.addEventListener)media.addEventListener('change',()=>{if(themeChoice==='auto'){applyPalette();drawPaletteFields()}});
changeTheme(themeChoice);

api('/v1/owner/session').then(async data=>{csrf=data.csrf;$('signin').hidden=true;$('workspace').hidden=false;await refresh();await loadRegistryFunctional();await loadSemanticRegistry();}).catch(()=>{});
