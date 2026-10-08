'use strict';
let status, csrf, previewId, exportPoll, currentExport;
let scheduleDirty=false, scheduleSaving=false;
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
function exportDate(value){return new Intl.DateTimeFormat('ru-RU',{dateStyle:'short',timeStyle:'short',timeZone:(status.schedule||{}).timezone||'UTC'}).format(new Date(value));}
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
  document.body.classList.add('zip-workflow');
  document.querySelectorAll('article section').forEach(s=>s.hidden=s.id!=='export');
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
  if(status.workflow==='zip_export'){renderExports();return;}
  el('export').hidden=true;el('status').hidden=false;document.querySelector('[data-tab=export]').hidden=true;
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
document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('article section').forEach(s=>s.hidden=s.id!==b.dataset.tab);document.querySelectorAll('[data-tab]').forEach(x=>x.classList.toggle('active',x===b));}));
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
['schedule-enabled','schedule-time'].forEach(id=>el(id).addEventListener('input',()=>{scheduleDirty=true;el('save-export-schedule').disabled=scheduleSaving;}));
el('export-schedule-form').addEventListener('submit',async event=>{
  event.preventDefault();scheduleSaving=true;el('save-export-schedule').disabled=true;
  el('schedule-enabled').disabled=true;el('schedule-time').disabled=true;
  try{
    await action('set_export_schedule',{enabled:el('schedule-enabled').checked,time:el('schedule-time').value});
    scheduleDirty=false;await refresh();notice('Расписание сохранено. Оно действует без перезапуска дополнения.');
  }catch(error){notice(error.message);}finally{scheduleSaving=false;el('schedule-enabled').disabled=false;el('schedule-time').disabled=false;el('save-export-schedule').disabled=!scheduleDirty;}
});
document.querySelector('[data-tab=status]').classList.add('active');refresh().catch(e=>notice(e.message));

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
document.addEventListener('visibilitychange',()=>{if(document.hidden)el('tunnel-key').value='';});
