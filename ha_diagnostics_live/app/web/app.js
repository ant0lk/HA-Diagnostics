'use strict';
let status, csrf, previewId, exportPoll, currentExport;
let scheduleDirty=false, scheduleSaving=false;
let yandexDirty=false, yandexSaving=false;
let activeTab='home', yandexEvents=[], yandexSession, yandexNext, yandexEventsLoading=false;
let yandexFilter='all', yandexHistoryRevision, yandexEventGeneration=0, yandexRefreshQueued=false;
let yandexHistoryPending=0, yandexBackfillTimer;
let matchingData, matchingLoading=false, ruleDirty=false, haEditor, haEditorGeneration=0;
const el=id=>document.getElementById(id);
function notice(text){el('notice').textContent=text;}
async function action(op,args={}){
  const r=await fetch('api/action',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({op,args})});
  const d=await r.json();if(!r.ok){const messages={EXPORT_BUSY:'Архив уже собирается. Дождитесь завершения или отмените сбор.',DISK_LOW:'Недостаточно свободного места для создания архива.',SOURCE_UNAVAILABLE:'Home Assistant временно недоступен.',EXPORT_NOT_FOUND:'Архив больше недоступен. Создайте новый.',SCHEDULE_SAVE_FAILED:'Не удалось сохранить расписание. Проверьте свободное место и повторите попытку.'};throw Error(messages[d.error]||d.error||'Запрос отклонён');}return d;
}
function button(label,fn){const b=document.createElement('button');b.textContent=label;b.addEventListener('click',()=>fn().catch(e=>notice(e.message)));return b;}
function card(title,value){const d=document.createElement('div');d.className='card';const t=document.createElement('small');t.textContent=title;const v=document.createElement('strong');v.textContent=value;d.append(t,v);return d;}
function zipLink(job){
  const a=document.createElement('a');a.className='download';a.textContent='Скачать ZIP';
  a.href='api/exports/'+encodeURIComponent(job.export_id)+'/download';a.download=job.filename;return a;
}
function formatBytes(bytes){return bytes<1048576?(bytes/1024).toFixed(1)+' KiB':(bytes/1048576).toFixed(1)+' MiB';}
function panelTimezone(){return (status.schedule||{}).timezone||status.ha_timezone||'UTC';}
function exportDate(value){return new Intl.DateTimeFormat('ru-RU',{dateStyle:'short',timeStyle:'short',timeZone:panelTimezone()}).format(new Date(value));}
function renderAddon(){
  const zip=status.workflow==='zip_export';
  document.querySelectorAll('[data-workflow]').forEach(block=>block.hidden=(block.dataset.workflow==='zip_export')!==zip);
  el('addon-version').textContent=status.version||el('addon-version').textContent;
  el('addon-state').textContent=status.demo?'Демонстрационный режим · используются тестовые данные.':zip?(status.available?'Дополнение готово к сбору диагностического архива.':'Home Assistant недоступен. Для сбора нужен Live-профиль с доступом к Supervisor API.'):(status.mode==='live'?'Live-профиль · локальный диагностический архив.':'Режим импорта · локальный диагностический архив.');
}
function selectTab(id,focus=false){
  if(!['home','archive','yandex'].includes(id))return;
  activeTab=id;
  document.querySelectorAll('[data-page]').forEach(page=>page.hidden=page.id!==id);
  document.querySelectorAll('[data-tab]').forEach(tab=>{
    const selected=tab.dataset.tab===id;
    tab.classList.toggle('active',selected);tab.setAttribute('aria-selected',String(selected));tab.tabIndex=selected?0:-1;
    if(selected&&focus)tab.focus();
  });
  if(id==='yandex'&&status){refreshYandexEvents();refreshYandexLinks();}
}
function renderSchedule(){
  const schedule=status.schedule||{};
  if(!scheduleDirty&&!scheduleSaving){el('schedule-enabled').checked=!!schedule.enabled;el('schedule-time').value=schedule.time||'03:00';}
  el('save-export-schedule').disabled=!scheduleDirty||scheduleSaving;
  el('schedule-timezone').textContent=schedule.timezone?'Часовой пояс Home Assistant: '+schedule.timezone+(schedule.timezone_origin==='cached_ha_config'?' · последнее сохранённое значение':''):'Ожидаем часовой пояс Home Assistant. Автосбор начнётся после его получения.';
  const errors={DISK_LOW:'Недостаточно свободного места. Повторим попытку автоматически.',SOURCE_UNAVAILABLE:'Home Assistant недоступен. Повторим попытку автоматически.',SCHEDULE_TIMEZONE_UNAVAILABLE:'Не удалось обновить часовой пояс Home Assistant.',SCHEDULE_SAVE_FAILED:'Не удалось сохранить отметку запуска. Проверьте свободное место.',SCHEDULE_SETTINGS_INVALID:'Сохранённое расписание повреждено. Укажите настройки и сохраните их.',SCHEDULE_FAILED:'Не удалось выполнить автосбор.',EXPORT_FAILED:'Последний автосбор завершился ошибкой.'};
  let text=!schedule.enabled?'Автосохранение выключено.':schedule.next_run_at?'Ежедневно в '+schedule.time+' · '+(new Date(schedule.next_run_at)<=new Date(status.time)?'Ожидает сбор с ':'Следующий сбор: ')+exportDate(schedule.next_run_at):'Время по умолчанию — 03:00. Ожидаем сведения Home Assistant.';
  if(schedule.error)text+=' '+(errors[schedule.error]||'Ошибка автосбора: '+schedule.error);
  if(schedule.last_run_status==='cancelled')text+=' Последний автосбор отменён. Можно собрать ZIP вручную.';
  if(schedule.last_run_status==='failed'&&!schedule.error)text+=' Последний автосбор завершился ошибкой. Можно собрать ZIP вручную.';
  el('schedule-state').textContent=text;
}
const yandexErrors={YANDEX_TOKEN_REQUIRED:'Введите токен при первом подключении.',YANDEX_SETTINGS_REJECTED:'Проверьте токен, интервал проверки и срок хранения.',YANDEX_SAVE_FAILED:'Не удалось сохранить подключение. Проверьте свободное место.',YANDEX_STORAGE_UNAVAILABLE:'Не удалось прочитать или записать историю Яндекса.',YANDEX_SETTINGS_INVALID:'Сохранённые настройки повреждены. Введите токен и сохраните подключение заново.',YANDEX_AUTH_FAILED:'Яндекс отклонил токен. Проверьте срок его действия и право iot:view.',YANDEX_RATE_LIMIT:'Яндекс ограничил частоту запросов. Следующая проверка будет позже.',YANDEX_NETWORK_ERROR:'Нет связи с API Яндекса. Это пропуск наблюдения, а не офлайн устройств.',YANDEX_API_UNAVAILABLE:'API Яндекса временно недоступен.',YANDEX_API_FORMAT:'Ответ Яндекса не содержит ожидаемых данных.',YANDEX_DEVICE_NOT_FOUND:'Одно из устройств не найдено. Его отсутствие проверим по списку устройств.',YANDEX_DEVICE_LIMIT:'Достигнут предел: 1000 устройств. Источник отмечен как неполный.',YANDEX_RESPONSE_LIMIT:'Ответ Яндекса превысил допустимый размер.',YANDEX_REDIRECT_DENIED:'API Яндекса вернул неожиданное перенаправление.',YANDEX_POLL_TIMEOUT:'Проверка устройств не завершилась вовремя.',YANDEX_DEMO_DISABLED:'В демонстрационном режиме подключение реального аккаунта отключено.'};
yandexErrors.YANDEX_CLOCK_INVALID='Часы переведены назад. Проверки продолжатся после восстановления временного порядка.';
function renderYandex(){
  const y=status.yandex||{};
  if(!yandexDirty&&!yandexSaving){el('yandex-enabled').checked=!!y.enabled;el('yandex-poll').value=y.poll_seconds||60;el('yandex-retention').value=y.retention_days||30;}
  const unavailable=!y.available;
  ['yandex-enabled','yandex-token','yandex-poll','yandex-retention'].forEach(id=>el(id).disabled=unavailable||yandexSaving);
  el('save-yandex').disabled=unavailable||!yandexDirty||yandexSaving;
  const counts=y.counts||{};
  let text=unavailable?(status.demo?'Подключение доступно в установленном дополнении. Демо не обращается к Яндексу.':'Подключение временно недоступно.'):!y.configured?'Яндекс ещё не подключён.':!y.enabled?'Сбор выключен. Сохранённая история продолжает включаться в ZIP.':!y.last_poll_at?'Подключение сохранено. Ожидаем первую проверку.':'Устройств: '+y.devices+' · онлайн: '+(counts.online||0)+' · офлайн: '+(counts.offline||0)+' · нет наблюдения: '+(counts.unknown||0);
  if(y.error)text+=' '+(yandexErrors[y.error]||'Не удалось обновить историю Яндекса.');
  if(y.stale&&y.enabled)text+=' Последняя проверка устарела.';
  el('yandex-state').textContent=text;
  el('yandex-observation').textContent=y.last_poll_at?'Последняя проверка: '+exportDate(y.last_poll_at)+' · история хранится '+y.retention_days+' дней.':'';
  el('yandex-history-note').textContent='События «онлайн» и «оффлайн» и изменения доступности HA, сначала новые. Время проверки · '+panelTimezone()+'. Переход определяется с точностью до интервала проверки.';
}
function renderYandexEvents(){
  const list=el('yandex-event-list');list.replaceChildren();
  const dayFormat=new Intl.DateTimeFormat('ru-RU',{dateStyle:'long',timeZone:panelTimezone()});
  const timeFormat=new Intl.DateTimeFormat('ru-RU',{hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23',timeZone:panelTimezone()});
  let lastDay,group;
  for(const event of yandexEvents){
    const date=new Date(event.observed_at);if(Number.isNaN(date.getTime()))continue;
    const day=dayFormat.format(date);
    if(day!==lastDay){
      const heading=document.createElement('h4');heading.className='event-date';heading.textContent=day;
      group=document.createElement('ol');group.className='event-day';group.setAttribute('aria-label',day);list.append(heading,group);lastDay=day;
    }
    const row=document.createElement('li');row.className='event-row';
    const info=document.createElement('div'),title=document.createElement('div'),place=document.createElement('p');
    title.className='event-title';title.textContent='«'+event.device_name+'»: '+(event.status==='online'?'онлайн':'оффлайн');
    const home=document.createElement('span'),dot=document.createElement('span'),room=document.createElement('span');
    home.textContent=event.home_name||'Без дома';room.textContent=event.room_name||'Без комнаты';dot.className='event-dot';dot.textContent='●';
    place.className='event-place';place.append(home,dot,room);info.append(title,place);
    const comparison=document.createElement('p');comparison.className='event-comparison '+(event.comparison||'unknown');
    comparison.textContent=comparisonText(event);info.append(comparison);
    if(event.ha_observed_at){
      const observation=document.createElement('small');observation.className='comparison-observation';
      observation.textContent=(event.ha_origin==='history'?'История HA на ':'HA проверен: ')+timeFormat.format(new Date(event.ha_observed_at))+(event.ha_name?' · '+event.ha_name:'');
      observation.title=exportDate(event.ha_observed_at)+(event.ha_retrieved_at?' · дополнено '+exportDate(event.ha_retrieved_at):'');info.append(observation);
    }
    if(event.kind==='comparison'){
      const source=document.createElement('small');source.className='comparison-observation';source.textContent='Изменение доступности или привязки HA';info.append(source);
    }
    const time=document.createElement('time');time.dateTime=event.observed_at;time.textContent=timeFormat.format(date);time.title=day+' · '+time.textContent+' · '+panelTimezone();
    row.append(info,time);group.append(row);
  }
  el('more-yandex-events').hidden=!yandexNext;
  const emptyText=yandexFilter==='all'?'Событий пока нет. Они появятся после проверки статусов устройств.':yandexFilter==='match'?'Событий с совпадающими статусами нет.':'Событий с отличающимися статусами нет.';
  el('yandex-history-state').textContent=yandexHistoryPending?'Дополняем старые события по истории HA: '+yandexHistoryPending+'.':yandexEvents.length?'':(status.yandex||{}).configured?emptyText:'Подключите Яндекс и включите сбор, чтобы видеть события устройств.';
}
const haReasons={HA_ENTITY_MISSING:'Объект HA не найден',HA_ENTITY_NOT_FOUND:'Объект HA не найден или HA недоступен',HA_SOURCE_UNAVAILABLE:'Не удалось прочитать Home Assistant',HA_CATALOG_INVALID:'Не удалось прочитать реестр HA',HA_STATES_INVALID:'Не удалось прочитать состояния HA',HA_ENTITY_LIMIT:'В HA больше 5000 объектов: сопоставление временно недоступно',HA_NOT_OBSERVED:'Статус HA тогда не собирался',HA_OBSERVATION_STALE:'Проверка HA устарела',HA_UNKNOWN_STATE:'У HA нет достоверного состояния',HA_OUTSIDE_RETENTION:'Проверка HA вне срока хранения',YANDEX_IDENTITY_CHANGED:'ID у поставщика изменился — подтвердите привязку заново',YANDEX_CONNECTION_CHANGED:'Подключение Яндекса изменилось. Обновите список устройств.',YANDEX_CANDIDATE_CHANGED:'Предложение изменилось. Обновите подбор.',YANDEX_SKILL_NOT_FOUND:'Навык больше не найден. Обновите устройства.'};
Object.assign(haReasons,{HA_HISTORY_PENDING:'Читаем историю HA на время события',HA_HISTORY_EMPTY:'В истории HA нет данных на это время',HA_HISTORY_UNAVAILABLE:'Не удалось прочитать историю HA',HA_HISTORY_INVALID:'Не удалось определить исторический статус HA',HA_HISTORY_LIMIT:'История HA превысила предел чтения'});
function comparisonText(value){
  if(value.comparison==='unlinked')return 'Home Assistant: устройство не связано';
  const availability={available:'доступно',unavailable:'недоступно',unknown:'нет данных'}[value.ha_status]||'нет данных';
  const verdict=value.comparison==='mismatch'?'Статусы различаются':value.comparison==='match'?'Статусы совпадают':haReasons[value.ha_reason]||'Сравнение недоступно';
  return 'Home Assistant: '+availability+' · '+verdict;
}
async function matchingAction(op,args){
  const response=await fetch('api/action',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({op,args}),cache:'no-store'});
  const result=await response.json();
  if(!response.ok)throw Error(haReasons[result.error]||yandexErrors[result.error]||'Не удалось сохранить сопоставление. Проверьте выбранный объект и правило.');
  return result;
}
async function refreshYandexLinks(){
  if(matchingLoading)return;
  if(status.workflow!=='zip_export'){el('yandex-links-state').textContent='Сопоставление доступно в профиле диагностического ZIP.';return;}
  matchingLoading=true;el('refresh-yandex-links').disabled=true;
  try{
    const response=await fetch('api/yandex/links',{cache:'no-store'});
    if(!response.ok)throw Error('Не удалось обновить сопоставления. Попробуйте ещё раз.');
    const previous=matchingData?.session_id;matchingData=await response.json();
    if(previous&&previous!==matchingData.session_id){ruleDirty=false;el('ha-link-dialog').close();}
    renderYandexLinks();renderIdentityRules();
  }catch(error){el('yandex-links-state').textContent=error.message;}
  finally{matchingLoading=false;el('refresh-yandex-links').disabled=false;}
}
function renderYandexLinks(){
  if(!matchingData)return;
  const list=el('yandex-device-list');list.replaceChildren();
  const search=el('yandex-device-search').value.trim().toLocaleLowerCase('ru');
  const filtered=matchingData.devices.filter(device=>[device.device_name,device.home_name,device.room_name].some(value=>(value||'').toLocaleLowerCase('ru').includes(search)));
  const entities=new Map(matchingData.entities.map(entity=>[entity.entity_ref,entity]));
  for(const device of filtered.slice(0,100)){
    const row=document.createElement('div');row.className='matching-device';row.dataset.deviceRef=device.device_ref;
    const title=document.createElement('strong');title.textContent='«'+device.device_name+'»';
    const place=document.createElement('p');place.className='event-place';place.textContent=(device.home_name||'Без дома')+' ● '+(device.room_name||'Без комнаты');
    const current=document.createElement('p');current.className='event-comparison '+device.comparison;
    current.textContent='Яндекс: '+({online:'онлайн',offline:'оффлайн'}[device.status]||'нет данных')+' · '+comparisonText(device);
    row.append(title,place,current);
    if(device.ha_entity_ref){
      const target=entities.get(device.ha_entity_ref),description=document.createElement('p');description.className='matching-target';
      const method={exact:'Точное сопоставление по ID',suggestion:'Подтверждённое предложение',manual:'Ручная привязка'}[device.method]||'Привязка';
      description.textContent=method+' · '+(target?target.name+' · '+target.entity_id:'Объект не найден');row.append(description);
    }
    const controls=document.createElement('div');controls.className='matching-actions';
    controls.append(button('Подобрать',()=>openHaLink(device,'suggestion')),button(device.ha_entity_ref?'Изменить вручную':'Связать вручную',()=>openHaLink(device,'manual')));
    if(device.ha_entity_ref)controls.append(button('Убрать связь',async()=>{
      await matchingAction('set_yandex_link',{session_id:matchingData.session_id,device_ref:device.device_ref,entity_ref:null,method:'manual'});
      await refreshYandexLinks();notice('Связь удалена. Автоматическое правило для этого устройства отключено до новой привязки.');
    }));
    row.append(controls);list.append(row);
  }
  let message=matchingData.ha_error?(haReasons[matchingData.ha_error]||'Home Assistant недоступен. Сравнение временно невозможно.'):
    matchingData.ha_observed_at?'HA проверен: '+exportDate(matchingData.ha_observed_at)+'.':'';
  if(!matchingData.devices.length)message+=' Устройства появятся после подключения и первой проверки Яндекса.';
  else if(!filtered.length)message+=' Устройства не найдены.';
  else if(filtered.length>100)message+=' Показаны первые 100 из '+filtered.length+' устройств. Уточните поиск.';
  el('yandex-links-state').textContent=message.trim();
}
function renderIdentityRules(){
  if(ruleDirty||!matchingData)return;
  const select=el('yandex-rule-skill'),previous=select.value,skills=new Map();
  for(const device of matchingData.devices)if(device.skill_id){
    const names=skills.get(device.skill_id)||[];if(names.length<2)names.push(device.device_name);skills.set(device.skill_id,names);
  }
  select.replaceChildren(new Option('Выберите навык',''));
  for(const [id,names] of skills)select.add(new Option(names.map(name=>'«'+name+'»').join(', ')+' · '+id,id));
  if(skills.has(previous))select.value=previous;
  el('save-yandex-rule').disabled=!skills.size||!matchingData.session_id;
  updateIdentityRule();
}
function updateIdentityRule(){
  const skill=el('yandex-rule-skill').value,rule=matchingData?.rules.find(value=>value.skill_id===skill);
  el('yandex-rule-prefix').value=rule?.external_prefix||'';el('yandex-rule-trusted').checked=!!rule;
  el('delete-yandex-rule').hidden=!rule;
  el('yandex-rule-examples').textContent=(matchingData?.devices||[]).filter(device=>device.skill_id===skill).slice(0,3)
    .map(device=>'«'+device.device_name+'»: '+(device.external_id||'внешний ID отсутствует')).join(' · ');
}
function renderHaChoices(){
  if(!haEditor)return;
  const search=el('ha-entity-search').value.trim().toLocaleLowerCase('ru'),select=el('ha-entity-select'),previous=select.value;
  let entities=haEditor.entities.filter(entity=>[entity.name,entity.entity_id,entity.room_name,entity.platform].some(value=>(value||'').toLocaleLowerCase('ru').includes(search)));
  select.replaceChildren();
  if(haEditor.method==='manual')select.add(new Option('Выберите объект HA',''));
  for(const entity of entities.slice(0,100)){
    const candidate=haEditor.candidates?.find(value=>value.entity_ref===entity.entity_ref);
    const reasons=candidate?' · '+candidate.reasons.map(value=>({type:'тип',name:'название',similar_name:'похожее название',room:'комната'})[value]).join(', '):'';
    select.add(new Option(entity.name+' · '+entity.entity_id+(entity.room_name?' · '+entity.room_name:'')+reasons,entity.entity_ref));
  }
  if([...select.options].some(option=>option.value===previous))select.value=previous;
  el('ha-link-state').textContent=!entities.length?haEditor.method==='suggestion'?'Подходящих предложений нет. Выберите объект вручную.':'Объекты не найдены.':
    haEditor.method==='suggestion'?'Совпадения требуют подтверждения. Выберите подходящий объект.':entities.length>100?'Показаны первые 100 объектов. Уточните поиск.':'Выберите объект, который отражает доступность этого устройства.';
  if(matchingData.ha_error)el('ha-link-state').textContent=haReasons[matchingData.ha_error]||'Home Assistant недоступен.';
  el('manual-ha-link').hidden=haEditor.method==='manual';updateHaChoice();
}
function updateHaChoice(){
  const entity=haEditor?.entities.find(value=>value.entity_ref===el('ha-entity-select').value);
  el('confirm-ha-link').disabled=!entity||!!matchingData?.ha_error;
  el('ha-entity-detail').textContent=entity?(entity.room_name||'Без комнаты')+' · '+(entity.platform||'Без интеграции')+
    (entity.stable?'':' · У объекта нет устойчивого ID: после переименования понадобится новая привязка.') :'';
}
async function openHaLink(device,method){
  const generation=++haEditorGeneration;
  haEditor={device,method,session_id:matchingData.session_id,entities:matchingData.entities,candidates:[]};
  el('ha-link-device').textContent='«'+device.device_name+'» · '+(device.room_name||'Без комнаты');
  el('ha-entity-search').value='';el('ha-entity-select').replaceChildren();el('ha-entity-detail').textContent='';
  el('ha-link-title').textContent=method==='suggestion'?'Подбор объекта Home Assistant':'Ручная привязка';
  el('confirm-ha-link').disabled=true;el('manual-ha-link').hidden=method==='manual';
  if(!el('ha-link-dialog').open)el('ha-link-dialog').showModal();
  if(method==='suggestion'){
    el('ha-link-state').textContent='Подбираем по названию, комнате и типу…';
    try{
      const query=new URLSearchParams({session_id:haEditor.session_id,device_ref:device.device_ref});
      const response=await fetch('api/yandex/candidates?'+query,{cache:'no-store'});
      if(!response.ok)throw Error('Не удалось получить предложения. Обновите устройства или выберите вручную.');
      const result=await response.json();if(generation!==haEditorGeneration||!haEditor)return;
      haEditor.candidates=result.candidates||[];
      haEditor.entities=haEditor.candidates.map(candidate=>matchingData.entities.find(entity=>entity.entity_ref===candidate.entity_ref)).filter(Boolean);
    }catch(error){if(generation===haEditorGeneration)el('ha-link-state').textContent=error.message;return;}
  }
  if(generation===haEditorGeneration)renderHaChoices();
}
async function refreshYandexEvents(more=false){
  if(yandexEventsLoading){if(!more)yandexRefreshQueued=true;return;}
  if(status.workflow!=='zip_export'){
    el('yandex-history-state').textContent='История Яндекса доступна в профиле диагностического ZIP.';return;
  }
  yandexEventsLoading=true;el('refresh-yandex-events').disabled=true;el('more-yandex-events').disabled=true;
  const generation=yandexEventGeneration;
  if(!yandexEvents.length)el('yandex-history-state').textContent='Загрузка событий…';
  try{
    const query=new URLSearchParams({comparison:yandexFilter});
    if(more&&yandexNext)query.set('before_event_id',yandexNext);
    const response=await fetch('api/yandex/events?'+query,{cache:'no-store'});
    if(!response.ok)throw Error('Не удалось загрузить историю. Попробуйте обновить её.');
    const feed=await response.json(),incoming=feed.events||[];
    if(generation!==yandexEventGeneration)return;
    const sameSession=yandexSession===feed.session_id;
    const sameRevision=yandexHistoryRevision===feed.history_revision;
    // Backfill can alter older loaded pages and their filter membership.
    // Restart pagination when those comparisons change.
    if(more&&(!sameSession||!sameRevision)){yandexRefreshQueued=true;return;}
    // A full new page with no overlap means more than a page changed between
    // refreshes. Restart pagination so a gap cannot be hidden in the list.
    const overlap=incoming.some(event=>yandexEvents.some(old=>old.event_id===event.event_id));
    const retain=sameSession&&sameRevision&&(more||overlap);
    const events=new Map((retain?yandexEvents:[]).map(event=>[event.event_id,event]));
    for(const event of incoming)if(['online','offline'].includes(event.status))events.set(event.event_id,event);
    yandexEvents=[...events.values()].filter(event=>event.observed_at>=feed.retained_from).sort((a,b)=>b.event_id-a.event_id);
    if(more||!retain)yandexNext=feed.next_before_event_id;
    yandexSession=feed.session_id;yandexHistoryRevision=feed.history_revision;yandexHistoryPending=feed.history_pending||0;renderYandexEvents();
    clearTimeout(yandexBackfillTimer);
    if(yandexHistoryPending)yandexBackfillTimer=setTimeout(()=>{if(activeTab==='yandex')refreshYandexEvents();},2000);
  }catch(error){if(generation===yandexEventGeneration)el('yandex-history-state').textContent=error.message;}
  finally{
    yandexEventsLoading=false;el('refresh-yandex-events').disabled=false;el('more-yandex-events').disabled=false;
    if(yandexRefreshQueued){yandexRefreshQueued=false;refreshYandexEvents();}
  }
}
function resetYandexEvents(){
  yandexEventGeneration++;yandexEvents=[];yandexNext=null;yandexHistoryRevision=undefined;
  renderYandexEvents();return refreshYandexEvents();
}
function renderExportList(id,jobs,emptyText){
  const list=el(id);list.replaceChildren();
  for(const job of jobs){
    const d=document.createElement('div');d.className='export-row';
    const info=document.createElement('div'),title=document.createElement('strong'),details=document.createElement('small');
    title.textContent=exportDate(job.started_at);
    details.textContent=formatBytes(job.bytes)+' · '+job.completed_sources+' источников'+(job.demo?' · демо':'')+(job.issues?' · есть пробелы':'');
    info.append(title,details);d.append(info,zipLink(job),button('Удалить',async()=>{await action('delete_export',{export_id:job.export_id});await refresh();}));list.append(d);
  }
  if(!jobs.length)list.textContent=emptyText;
}
function renderExports(){
  const jobs=status.exports||[];currentExport=jobs.find(j=>j.status==='collecting')||jobs[0];
  el('create-zip').disabled=!status.available||!!jobs.find(j=>j.status==='collecting');
  el('cancel-zip').hidden=!currentExport||currentExport.status!=='collecting';
  el('download-zip').hidden=!currentExport||currentExport.status!=='ready';
  el('export-progress').classList.toggle('collecting',!!currentExport&&currentExport.status==='collecting');
  if(currentExport){
    const j=currentExport;
    if(j.status==='ready'){
      el('export-progress').textContent='Архив готов · '+formatBytes(j.bytes)+' · '+j.completed_sources+' источников'+(j.issues?' · '+j.issues+' источников с пробелами (подробности в manifest.json)':'');
      el('download-zip').href='api/exports/'+encodeURIComponent(j.export_id)+'/download';el('download-zip').download=j.filename;
    }else if(j.status==='collecting'){
      el('export-progress').textContent=(j.kind==='automatic'?'Автосбор: ':'Собираем: ')+(j.current_source||'подготовка')+' · обработано источников: '+j.completed_sources;
    }else el('export-progress').textContent=j.status==='cancelled'?'Сбор отменён. Можно создать новый архив.':'Не удалось создать архив: '+(j.error||'ошибка сбора');
  }else el('export-progress').textContent='Архив ещё не создавался.';
  renderSchedule();
  renderYandex();
  if(activeTab==='yandex'){refreshYandexEvents();refreshYandexLinks();}
  renderExportList('automatic-export-list',jobs.filter(j=>j.status==='ready'&&j.kind==='automatic'),'Автоархивов пока нет. Первый появится после сбора по расписанию.');
  renderExportList('export-list',jobs.filter(j=>j.status==='ready'&&j.kind!=='automatic'),'Ручных архивов пока нет. Нажмите «Собрать ZIP-архив».');
  notice(status.demo?'Демонстрационный режим: ZIP содержит тестовые данные, без подключения к вашей установке HA.':status.available?'История и события: 24 часа. Логи: за всё доступное время.':'Home Assistant недоступен. Для сбора нужен Live-профиль дополнения с доступом к Supervisor API.');
  clearTimeout(exportPoll);
  exportPoll=setTimeout(()=>refresh().catch(exportRetry),jobs.some(j=>j.status==='collecting')?1500:30000);
}
function exportRetry(error){notice('Не удалось обновить прогресс. '+error.message);exportPoll=setTimeout(()=>refresh().catch(exportRetry),3000);}
function renderSources(sources){
  el('source-list').replaceChildren();
  for(const s of sources){
    const d=document.createElement('div');d.className='source';d.dataset.source=s.source_id;
    const name=document.createElement('strong');name.textContent=s.source_id;d.append(name);
    for(const [key,title] of [['collect','Собирать локально'],['disclose','Передавать ChatGPT']]){
      const l=document.createElement('label'),i=document.createElement('input');i.type='checkbox';i.dataset.key=key;i.checked=!!s[key];l.append(i,document.createTextNode(title));d.append(l);
    }
    el('source-list').append(d);
  }
}
function renderArtifacts(){
  el('artifact-list').replaceChildren();
  for(const a of status.artifacts.artifacts||[]){
    const d=document.createElement('div');d.className='artifact';const title=document.createElement('strong');
    title.textContent=a.artifact_id+' · '+a.kind;const info=document.createElement('p');info.textContent=(a.approved?'Доступен ChatGPT':'Только локально')+' · импорт '+a.imported_at;
    d.append(title,info,button('Посмотреть очищенный текст',async()=>{const r=await action('read_local_artifact',{artifact_id:a.artifact_id});el('artifact-content').textContent=r.content+(r.truncated?'\n[Показана первая часть материала]':'');}),
      button(a.approved?'Отозвать доступ':'Разрешить ChatGPT',async()=>{await action('approve_artifact',{artifact_id:a.artifact_id,approved:!a.approved});await refresh();}),
      button('Удалить копию',async()=>{await action('delete_artifact',{artifact_id:a.artifact_id});el('artifact-content').textContent='';await refresh();}));
    el('artifact-list').append(d);
  }
  if(!(status.artifacts.artifacts||[]).length)el('artifact-list').textContent='Импортированных материалов нет.';
}
async function refresh(){
  const r=await fetch('api/status');if(!r.ok)throw Error('Административная сессия не подтверждена');status=await r.json();csrf=status.csrf;
  renderAddon();
  if(status.workflow==='zip_export'){renderExports();return;}
  renderYandex();
  el('metrics').replaceChildren(card('Режим',status.mode==='live'?'Live · настройка':'Импорт'),card('Собственный архив',(status.storage_bytes/1048576).toFixed(1)+' MiB'),card('Часовой пояс HA',status.ha_timezone));
  el('timezone-origin').textContent=status.timezone_origin==='observed_ha_config'?'Пояс прочитан из HA.':'Пояс задан локально; сведения HA ещё не получены.';
  el('coverage').replaceChildren();
  for(const s of status.sources){const d=document.createElement('div');d.className='source';d.textContent=s.source_id+' · '+s.status+' · последнее наблюдение: '+(s.latest_observed_at||'нет');el('coverage').append(d);}
  for(const c of status.coverage||[]){const details=document.createElement('details'),summary=document.createElement('summary'),text=document.createElement('pre');summary.textContent=c.source_id+' · покрытие последних 24 часов: '+c.status;text.textContent=JSON.stringify(c,null,2);details.append(summary,text);el('coverage').append(details);}if(!status.sources.length)el('coverage').textContent='Данные ещё не собраны. Отсутствие записей не означает отсутствие ошибок.';
  el('live-preview').textContent=JSON.stringify(status.local_log_preview||[],null,2);el('policy').value=JSON.stringify(status.policy,null,2);renderSources(status.policy.sources);renderArtifacts();
  el('audit-content').textContent=(status.audit||[]).map(x=>x.at+' · '+x.tool+' · '+x.decision+' · '+x.bytes+' байт · '+x.latency_ms+' мс'+(x.error_code?' · '+x.error_code:'')).join('\n')||'Обращений ещё нет. Показаны последние 100 записей.';
  const last=(status.audit||[]).filter(x=>x.decision==='allow').at(-1);el('transport-state').textContent='Транспорт: '+status.transport+' · последний разрешённый MCP-вызов: '+(last?last.at:'нет');
  const tunnel=status.tunnel||{};
  el('tunnel-id').value=tunnel.tunnel_id||'';
  el('save-tunnel').disabled=!tunnel.available;
  el('tunnel-state').textContent=!tunnel.available?(tunnel.reason==='TRANSPORT_CONFLICT'?'Настроен HTTPS relay. Для перехода на туннель сначала отзовите и удалите настройки relay локально.':'Настройка туннеля временно недоступна.'):(tunnel.restart_required?'Настройки сохранены. Перезапустите HA-Diagnostics.':tunnel.configured?'Туннель настроен. Соединение с ChatGPT ещё нужно проверить.':'Туннель ещё не настроен.');
  notice(status.demo?'Локальный import-only режим разработки. Изоляция HA OS и подключение ChatGPT не проверены.':'Предварительный alpha-выпуск. Перед подключением проверьте очистку и разрешения.');
}
document.querySelectorAll('[data-tab]').forEach(tab=>{
  tab.addEventListener('click',()=>selectTab(tab.dataset.tab));
  tab.addEventListener('keydown',event=>{
    const tabs=[...document.querySelectorAll('[data-tab]')],index=tabs.indexOf(tab);
    const next=event.key==='ArrowRight'?(index+1)%tabs.length:event.key==='ArrowLeft'?(index+tabs.length-1)%tabs.length:event.key==='Home'?0:event.key==='End'?tabs.length-1:null;
    if(next!==null){event.preventDefault();selectTab(tabs[next].dataset.tab,true);}
  });
});
document.querySelectorAll('[data-open-tab]').forEach(button=>button.addEventListener('click',()=>selectTab(button.dataset.openTab,true)));
function bind(id,fn){el(id).addEventListener('click',()=>fn().catch(e=>notice(e.message)));}
bind('discover',async()=>{const d=await action('discover_sources');renderSources(d.sources.map(s=>({...s,collect:true,disclose:false})));notice('Найденные источники отмечены для сбора; передачу выберите отдельно.');});
bind('save-sources',async()=>{const p={...status.policy};p.sources=[...document.querySelectorAll('.source[data-source]')].map(d=>({source_id:d.dataset.source,collect:d.querySelector('[data-key=collect]').checked,disclose:d.querySelector('[data-key=disclose]').checked}));p.collection_enabled=true;await action('set_policy',{policy:p});await refresh();});
bind('select-entities',async()=>{const d=await action('discover_entities');const p={...status.policy,entity_ids:d.entities.map(x=>x.entity_id),entity_refs:d.entities.map(x=>x.entity_ref)};await action('set_policy',{policy:p});el('entity-list').textContent=JSON.stringify(d,null,2);await refresh();notice(d.truncated?'Достигнут предел alpha: выбрано 1000 сущностей; остальные не собираются.':'Выбрано допустимых сущностей: '+d.entities.length);});
bind('save-policy',async()=>{await action('set_policy',{policy:JSON.parse(el('policy').value)});await refresh();});
bind('stop',async()=>{await action('pause_collection');await refresh();});
bind('revoke',async()=>{await action('revoke_access');await refresh();});
bind('delete',async()=>{if(!window.confirm('Удалить только архив HA-Diagnostics? Данные HA и уже отправленные сообщения останутся.'))return;await action('delete_archive');el('artifact-content').textContent='';await refresh();});
bind('preview',async()=>{
  el('commit').disabled=true;previewId=null;const f=el('file').files[0];if(!f||f.size>20*1048576)throw Error('Выберите .log/.txt/.json до 20 MiB');
  const bytes=new Uint8Array(await f.arrayBuffer());let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));
  const d=await action('import_preview',{filename:f.name,content_base64:btoa(binary)});previewId=d.preview_id;el('preview-content').textContent=d.content+'\n\n'+d.coverage_notes.join('\n');el('commit').disabled=false;notice('Показан только очищенный текст. Проверьте неизвестные секреты вручную.');
});
el('file').addEventListener('change',()=>{previewId=null;el('commit').disabled=true;el('preview-content').textContent='';});
bind('commit',async()=>{await action('import_commit',{preview_id:previewId,share_with_chatgpt:el('share-import').checked});previewId=null;el('commit').disabled=true;await refresh();});
bind('show-evidence',async()=>{const r=await action('read_evidence',{record_id:el('evidence-id').value.trim()});el('evidence-content').textContent=JSON.stringify(r,null,2);});
bind('refresh-audit',refresh);
bind('create-zip',async()=>{el('create-zip').disabled=true;try{await action('start_export',{history_hours:24});await refresh();}catch(error){el('create-zip').disabled=false;throw error;}});
bind('cancel-zip',async()=>{if(currentExport){await action('cancel_export',{export_id:currentExport.export_id});await refresh();}});
bind('refresh-zip',refresh);
bind('refresh-yandex-events',resetYandexEvents);
bind('more-yandex-events',async()=>{await refreshYandexEvents(true);});
el('yandex-event-filter').addEventListener('change',()=>{yandexFilter=el('yandex-event-filter').value;resetYandexEvents();});
bind('refresh-yandex-links',refreshYandexLinks);
el('yandex-device-search').addEventListener('input',renderYandexLinks);
el('yandex-rule-skill').addEventListener('change',()=>{ruleDirty=true;updateIdentityRule();});
['yandex-rule-prefix','yandex-rule-trusted'].forEach(id=>el(id).addEventListener('input',()=>{ruleDirty=true;}));
el('yandex-rule-form').addEventListener('submit',async event=>{
  event.preventDefault();el('save-yandex-rule').disabled=true;
  try{
    await matchingAction('set_yandex_identity_rule',{session_id:matchingData.session_id,skill_id:el('yandex-rule-skill').value,external_prefix:el('yandex-rule-prefix').value,enabled:true});
    ruleDirty=false;await refreshYandexLinks();await refreshYandexEvents();notice('Правило сохранено. Подходящие устройства связываются автоматически; старые события дополняются по истории HA.');
  }catch(error){notice(error.message);}finally{el('save-yandex-rule').disabled=false;}
});
bind('delete-yandex-rule',async()=>{
  await matchingAction('set_yandex_identity_rule',{session_id:matchingData.session_id,skill_id:el('yandex-rule-skill').value,enabled:false});
  ruleDirty=false;await refreshYandexLinks();notice('Правило удалено. Подтверждённые предложения и ручные привязки сохранены.');
});
bind('close-ha-link',async()=>{el('ha-link-dialog').close();});
el('ha-link-dialog').addEventListener('close',()=>{haEditor=null;haEditorGeneration++;});
el('ha-entity-search').addEventListener('input',renderHaChoices);
el('ha-entity-select').addEventListener('change',updateHaChoice);
bind('manual-ha-link',async()=>{if(haEditor)await openHaLink(haEditor.device,'manual');});
el('ha-link-form').addEventListener('submit',async event=>{
  event.preventDefault();if(!haEditor)return;el('confirm-ha-link').disabled=true;
  try{
    await matchingAction('set_yandex_link',{session_id:haEditor.session_id,device_ref:haEditor.device.device_ref,entity_ref:el('ha-entity-select').value,method:haEditor.method});
    el('ha-link-dialog').close();await refreshYandexLinks();await refreshYandexEvents();notice('Связь сохранена. Старые события дополняются статусом из истории Home Assistant на время события.');
  }catch(error){el('ha-link-state').textContent=error.message;}finally{updateHaChoice();}
});
['schedule-enabled','schedule-time'].forEach(id=>el(id).addEventListener('input',()=>{scheduleDirty=true;el('save-export-schedule').disabled=scheduleSaving;}));
el('export-schedule-form').addEventListener('submit',async event=>{
  event.preventDefault();scheduleSaving=true;el('save-export-schedule').disabled=true;
  el('schedule-enabled').disabled=true;el('schedule-time').disabled=true;
  try{
    await action('set_export_schedule',{enabled:el('schedule-enabled').checked,time:el('schedule-time').value});
    scheduleDirty=false;await refresh();notice('Расписание сохранено. Оно действует без перезапуска дополнения.');
  }catch(error){notice(error.message);}finally{scheduleSaving=false;el('schedule-enabled').disabled=false;el('schedule-time').disabled=false;el('save-export-schedule').disabled=!scheduleDirty;}
});
['yandex-enabled','yandex-token','yandex-poll','yandex-retention'].forEach(id=>el(id).addEventListener('input',()=>{yandexDirty=true;el('save-yandex').disabled=yandexSaving||!(status.yandex||{}).available;}));
el('yandex-form').addEventListener('submit',async event=>{
  event.preventDefault();yandexSaving=true;el('save-yandex').disabled=true;
  const token=el('yandex-token');
  const settings={enabled:el('yandex-enabled').checked,poll_seconds:Number(el('yandex-poll').value),retention_days:Number(el('yandex-retention').value)};
  if(token.value)settings.token=token.value;
  token.value='';renderYandex();
  try{
    const response=await fetch('api/yandex',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(settings),cache:'no-store'});
    settings.token=null;
    const result=await response.json();
    if(!response.ok)throw Error(yandexErrors[result.error]||'Не удалось сохранить подключение Яндекса.');
    yandexDirty=false;await refresh();notice('Подключение Яндекса сохранено. Настройки действуют без перезапуска.');
  }catch(error){notice(error.message);}finally{settings.token=null;token.value='';yandexSaving=false;renderYandex();}
});
selectTab('home');refresh().catch(e=>notice(e.message));

document.getElementById('tunnel-form').addEventListener('submit',async event=>{
  event.preventDefault();const key=el('tunnel-key');const save=el('save-tunnel');
  save.disabled=true;
  try{
    const body=JSON.stringify({tunnel_id:el('tunnel-id').value.trim(),runtime_key:key.value});key.value='';
    const response=await fetch('api/tunnel',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body,cache:'no-store'});
    if(!response.ok)throw Error('Не удалось сохранить туннель. Проверьте ID, ключ и отсутствие настроенного relay.');
    await refresh();notice('Туннель сохранён. Перезапустите HA-Diagnostics на странице приложения в Home Assistant.');
  }catch(error){notice(error.message);}finally{key.value='';save.disabled=!(status.tunnel||{}).available;}
});
document.addEventListener('visibilitychange',()=>{if(document.hidden){el('tunnel-key').value='';el('yandex-token').value='';}});
