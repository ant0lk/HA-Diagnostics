'use strict';
let status, csrf, previewId;
const el=id=>document.getElementById(id);
function notice(text){el('notice').textContent=text;}
async function action(op,args={}){
  const r=await fetch('api/action',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({op,args})});
  const d=await r.json();if(!r.ok)throw Error(d.error||'Запрос отклонён');return d;
}
function button(label,fn){const b=document.createElement('button');b.textContent=label;b.addEventListener('click',()=>fn().catch(e=>notice(e.message)));return b;}
function card(title,value){const d=document.createElement('div');d.className='card';const t=document.createElement('small');t.textContent=title;const v=document.createElement('strong');v.textContent=value;d.append(t,v);return d;}
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
  el('metrics').replaceChildren(card('Режим',status.mode==='live'?'Live · настройка':'Импорт'),card('Собственный архив',(status.storage_bytes/1048576).toFixed(1)+' MiB'),card('Часовой пояс HA',status.ha_timezone));
  el('timezone-origin').textContent=status.timezone_origin==='observed_ha_config'?'Пояс прочитан из HA.':'Пояс задан локально; сведения HA ещё не получены.';
  el('coverage').replaceChildren();
  for(const s of status.sources){const d=document.createElement('div');d.className='source';d.textContent=s.source_id+' · '+s.status+' · последнее наблюдение: '+(s.latest_observed_at||'нет');el('coverage').append(d);}
  for(const c of status.coverage||[]){const details=document.createElement('details'),summary=document.createElement('summary'),text=document.createElement('pre');summary.textContent=c.source_id+' · покрытие последних 24 часов: '+c.status;text.textContent=JSON.stringify(c,null,2);details.append(summary,text);el('coverage').append(details);}if(!status.sources.length)el('coverage').textContent='Данные ещё не собраны. Отсутствие записей не означает отсутствие ошибок.';
  el('live-preview').textContent=JSON.stringify(status.local_log_preview||[],null,2);el('policy').value=JSON.stringify(status.policy,null,2);renderSources(status.policy.sources);renderArtifacts();
  el('audit-content').textContent=(status.audit||[]).map(x=>x.at+' · '+x.tool+' · '+x.decision+' · '+x.bytes+' байт · '+x.latency_ms+' мс'+(x.error_code?' · '+x.error_code:'')).join('\n')||'Обращений ещё нет. Показаны последние 100 записей.';
  const last=(status.audit||[]).filter(x=>x.decision==='allow').at(-1);el('transport-state').textContent='Транспорт: '+status.transport+' · последний разрешённый MCP-вызов: '+(last?last.at:'нет');
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
document.querySelector('[data-tab=status]').classList.add('active');refresh().catch(e=>notice(e.message));
