/* ─── Config ─── */
const cfg = window.SV_CONFIG || {};
const SCOPES       = 'https://www.googleapis.com/auth/gmail.readonly';
const BATCH        = 3;
const IDB_MAX_ROWS = 30;
const WORKER_URL   = 'https://securevision-register.icivil-jmr.workers.dev';
const REDIRECT_URI = (location.origin + location.pathname).replace(/\/?$/, '/');

/* ─── State ─── */
const state = {
  armed:false, allEvents:[], pageToken:null, latest:null,
  accessToken:'', tokenExpiry:0, selectedEmail:'', gmailReady:false,
};

const LS_REFRESH = 'sv_refresh_token';
const LS_EXPIRY  = 'sv_token_expiry';
const LS_ACCESS  = 'sv_access_token';

const els = {
  date:document.getElementById('clock-date'),
  time:document.getElementById('clock-time'),
  btnGmail:document.getElementById('btn-gmail'),
  btnArm:document.getElementById('btn-arm'),
  btnEye:document.getElementById('btn-eye'),
  btnConfig:document.getElementById('btn-config'),
  latestImage:document.getElementById('latest-image'),
  latestEmpty:document.getElementById('latest-empty'),
  btnOpenLatest:document.getElementById('btn-open-latest'),
  btnDownloadLatest:document.getElementById('btn-download-latest'),
  historyGroups:document.getElementById('history-groups'),
  btnLoadMore:document.getElementById('btn-load-more'),
  viewerModal:document.getElementById('viewer-modal'),
  viewerContent:document.getElementById('viewer-content'),
  gmailModal:document.getElementById('gmail-modal'),
  alarmModal:document.getElementById('alarm-modal'),
  eyeModal:document.getElementById('eye-modal'),
  configModal:document.getElementById('config-modal'),
  gmailAccount:document.getElementById('gmail-account'),
  gmailStatus:document.getElementById('gmail-status'),
  btnGmailConnect:document.getElementById('btn-gmail-connect'),
  btnLoadHistory:document.getElementById('btn-load-history'),
  btnClearCache:document.getElementById('btn-clear-cache'),
  gmailQuery:document.getElementById('gmail-query'),
  alarmStatus:document.getElementById('alarm-status'),
  btnArmOn:document.getElementById('btn-arm-on'),
  btnArmOff:document.getElementById('btn-arm-off'),
  allowedEmail:document.getElementById('allowed-email'),
  btnSaveConfig:document.getElementById('btn-save-config'),
};

/* ─── Helpers ─── */
function pad(v){return String(v).padStart(2,'0');}
function toast(msg){const t=document.createElement('div');t.className='toast';t.textContent=msg;document.getElementById('toast-container').appendChild(t);setTimeout(()=>t.remove(),2600);}
function openModal(el){el.classList.remove('hidden');}
function closeModal(el){el.classList.add('hidden');}
function updateClock(){
  const n=new Date();
  els.date.textContent=`${pad(n.getDate())}-${pad(n.getMonth()+1)}-${n.getFullYear()}`;
  els.time.textContent=`${pad(n.getHours())}:${pad(n.getMinutes())}:${pad(n.getSeconds())}`;
}
function toggleArm(force){
  state.armed=typeof force==='boolean'?force:!state.armed;
  els.btnArm.textContent=state.armed?'🔔':'🔕';
  els.btnArm.classList.toggle('armed',state.armed);
  els.alarmStatus.textContent=state.armed?'Armada':'Desarmada';
}
function formatHourLabel(d){const x=new Date(d),h=x.getHours();return `Hoy ${pad(h)}:00 - ${pad(h+1)}:00`;}
function formatTime(d){const x=new Date(d);return `${pad(x.getHours())}:${pad(x.getMinutes())}:${pad(x.getSeconds())}`;}
function formatDate(d){const x=new Date(d);return `${pad(x.getDate())}-${pad(x.getMonth()+1)}-${x.getFullYear()}`;}

/* ─── PKCE ─── */
function randomBase64Url(len){const a=new Uint8Array(len);crypto.getRandomValues(a);return btoa(String.fromCharCode(...a)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');}
async function sha256Base64Url(str){const b=new TextEncoder().encode(str);const h=await crypto.subtle.digest('SHA-256',b);return btoa(String.fromCharCode(...new Uint8Array(h))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');}

/* ─── Token storage ─── */
function saveTokens(access,refresh,expiresIn){
  const expiry=Date.now()+(expiresIn-60)*1000;
  state.accessToken=access;state.tokenExpiry=expiry;
  localStorage.setItem(LS_ACCESS,access);localStorage.setItem(LS_EXPIRY,String(expiry));
  if(refresh)localStorage.setItem(LS_REFRESH,refresh);
}
function loadStoredTokens(){state.accessToken=localStorage.getItem(LS_ACCESS)||'';state.tokenExpiry=Number(localStorage.getItem(LS_EXPIRY)||0);}
function isTokenValid(){return !!state.accessToken&&Date.now()<state.tokenExpiry;}
function clearTokens(){state.accessToken='';state.tokenExpiry=0;localStorage.removeItem(LS_ACCESS);localStorage.removeItem(LS_EXPIRY);localStorage.removeItem(LS_REFRESH);}

async function refreshAccessToken(){
  const rt=localStorage.getItem(LS_REFRESH);if(!rt)return false;
  try{const res=await fetch(`${WORKER_URL}/sv-refresh`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:rt})});
    const data=await res.json();if(!res.ok||!data.access_token)return false;
    saveTokens(data.access_token,null,data.expires_in);return true;
  }catch{return false;}
}
async function ensureToken(){if(isTokenValid())return true;return refreshAccessToken();}

async function startLogin(){
  const verifier=randomBase64Url(64),challenge=await sha256Base64Url(verifier);
  sessionStorage.setItem('sv_pkce_verifier',verifier);
  const params=new URLSearchParams({response_type:'code',client_id:cfg.googleClientId,redirect_uri:REDIRECT_URI,scope:SCOPES,access_type:'offline',prompt:'consent',code_challenge:challenge,code_challenge_method:'S256'});
  location.href=`https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

async function handleOAuthCallback(){
  const params=new URLSearchParams(location.search);
  const code=params.get('code'),error=params.get('error');
  if(error){toast('Login cancelado.');return false;}
  if(!code)return false;
  history.replaceState({},'',location.pathname);
  const verifier=sessionStorage.getItem('sv_pkce_verifier');sessionStorage.removeItem('sv_pkce_verifier');
  if(!verifier){toast('Error PKCE.');return false;}
  els.gmailStatus.textContent='Obteniendo tokens...';
  try{const res=await fetch(`${WORKER_URL}/sv-exchange`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,code_verifier:verifier,redirect_uri:REDIRECT_URI})});
    const data=await res.json();if(!res.ok||!data.access_token){toast('Error: '+(data.error||'?'));return false;}
    saveTokens(data.access_token,data.refresh_token,data.expires_in);return true;
  }catch(e){toast('Error red: '+e.message);return false;}
}

async function fetchProfile(){
  const res=await fetch('https://www.googleapis.com/oauth2/v3/userinfo',{headers:{Authorization:`Bearer ${state.accessToken}`}});
  const data=await res.json();
  state.selectedEmail=data.email||'';
  els.gmailAccount.textContent=state.selectedEmail||'Sin cuenta';
  if((cfg.allowedEmail||'').trim()&&state.selectedEmail.toLowerCase()!==String(cfg.allowedEmail).trim().toLowerCase()){
    els.gmailStatus.textContent='Cuenta no permitida';toast('Cuenta no permitida.');clearTokens();return false;
  }
  state.gmailReady=true;els.gmailStatus.textContent='Cuenta validada';return true;
}

async function initAuth(){
  if(location.search.includes('code=')){const ok=await handleOAuthCallback();if(!ok){els.gmailStatus.textContent='Error en login';return;}}
  loadStoredTokens();
  if(isTokenValid()){await fetchProfile();autoLoadFromCache();return;}
  els.gmailStatus.textContent='Renovando sesión...';
  const ok=await refreshAccessToken();
  if(ok){await fetchProfile();autoLoadFromCache();return;}
  els.gmailStatus.textContent='Sin sesión. Pulsa Conectar.';
  els.btnGmailConnect.style.display='inline-flex';
}

/* ═══════════════════════════════════════════
   IndexedDB Cache
   ═══════════════════════════════════════════ */
const IDB_DB='sv_events',IDB_VER=1,IDB_STORE='events';

function openIDB(){
  return new Promise((res,rej)=>{
    const r=indexedDB.open(IDB_DB,IDB_VER);
    r.onupgradeneeded=e=>{const db=e.target.result;if(!db.objectStoreNames.contains(IDB_STORE))db.createObjectStore(IDB_STORE,{keyPath:'id'});};
    r.onsuccess=e=>res(e.target.result);r.onerror=e=>rej(e.target.error);
  });
}
async function idbGetAll(){const db=await openIDB();return new Promise((res,rej)=>{const r=db.transaction(IDB_STORE,'readonly').objectStore(IDB_STORE).getAll();r.onsuccess=e=>res(e.target.result||[]);r.onerror=e=>rej(e.target.error);});}
async function idbSaveMany(rows){if(!rows.length)return;const db=await openIDB();return new Promise((res,rej)=>{const tx=db.transaction(IDB_STORE,'readwrite');const s=tx.objectStore(IDB_STORE);rows.forEach(r=>s.put(r));tx.oncomplete=res;tx.onerror=e=>rej(e.target.error);});}
async function idbClear(){const db=await openIDB();return new Promise((res,rej)=>{const tx=db.transaction(IDB_STORE,'readwrite');tx.objectStore(IDB_STORE).clear();tx.oncomplete=res;tx.onerror=e=>rej(e.target.error);});}
async function idbPrune(){
  const all=await idbGetAll();if(all.length<=IDB_MAX_ROWS)return;
  all.sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
  const toDelete=all.slice(IDB_MAX_ROWS);
  const db=await openIDB();return new Promise((res,rej)=>{const tx=db.transaction(IDB_STORE,'readwrite');const s=tx.objectStore(IDB_STORE);toDelete.forEach(r=>s.delete(r.id));tx.oncomplete=res;tx.onerror=e=>rej(e.target.error);});
}

function eventToCacheRow(ev){const{mediaUrl,thumb,...rest}=ev;return rest;}
function cacheRowToEvent(row){
  if(!row.data)return null;
  try{const bytes=base64UrlToUint8Array(row.data);const mediaUrl=bytesToBlobUrl(bytes,row.mimeType||'application/octet-stream');return{...row,mediaUrl,thumb:row.type==='photo'?mediaUrl:null};}
  catch{return null;}
}

/* Auto-cargar caché al inicio; si vacío, fetch Gmail automático */
async function autoLoadFromCache(){
  try{
    const rows=await idbGetAll();
    if(rows.length){
      const events=rows.map(cacheRowToEvent).filter(Boolean).sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
      state.allEvents=events;state.latest=events.find(x=>x.type==='photo')||events[0]||null;
      renderLatest();renderHistory();
      els.gmailStatus.textContent=`Caché: ${events.length} alertas`;
      loadVideoThumbnails();
      setTimeout(()=>silentGmailCheck(),1500);
    } else {
      els.gmailStatus.textContent='Cargando alertas...';
      await loadHistory();
    }
  }catch(e){console.warn('autoLoad:',e);}
}

/* Verificación silenciosa: solo actualiza si hay nuevos */
async function silentGmailCheck(){
  if(!state.gmailReady)return;
  try{
    const cachedIds=new Set(state.allEvents.map(x=>x.id));
    state.pageToken=null;
    const fresh=await fetchNextBatch();
    const trulyNew=fresh.filter(ev=>!cachedIds.has(ev.id));
    if(!trulyNew.length){els.gmailStatus.textContent=`${state.allEvents.length} alertas`;return;}
    await idbSaveMany(trulyNew.map(eventToCacheRow));await idbPrune();
    state.allEvents=[...trulyNew,...state.allEvents].sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
    state.latest=state.allEvents.find(x=>x.type==='photo')||state.allEvents[0]||null;
    renderLatest();renderHistory();
    els.gmailStatus.textContent=`${state.allEvents.length} alertas`;
    toast(`${trulyNew.length} alerta${trulyNew.length>1?'s':''} nueva${trulyNew.length>1?'s':''}`);
    loadVideoThumbnails();
  }catch(e){console.warn('silentCheck:',e);}
}

/* ─── Gmail API helpers ─── */
function base64UrlToUint8Array(b64){const base64=b64.replace(/-/g,'+').replace(/_/g,'/');const padded=base64+'='.repeat((4-(base64.length%4))%4);const raw=atob(padded);const arr=new Uint8Array(raw.length);for(let i=0;i<raw.length;i++)arr[i]=raw.charCodeAt(i);return arr;}
function bytesToBlobUrl(bytes,mime){return URL.createObjectURL(new Blob([bytes],{type:mime||'application/octet-stream'}));}
function guessType(filename,mimeType){const n=(filename||'').toLowerCase(),m=(mimeType||'').toLowerCase();if(m.startsWith('image/')||/\.(jpg|jpeg|png|webp|gif)$/i.test(n))return 'photo';if(m.startsWith('video/')||/\.(mp4|webm|mov|avi|mkv)$/i.test(n))return 'video';return '';}
async function fetchAttachment(messageId,attachmentId){const res=await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/attachments/${attachmentId}`,{headers:{Authorization:`Bearer ${state.accessToken}`}});return res.json();}
function findParts(parts,out=[]){for(const p of parts||[]){if(p.parts?.length)findParts(p.parts,out);else out.push(p);}return out;}

/* ─── Rendering ─── */
function renderLatest(){
  const ev=state.latest;
  if(!ev){els.latestImage.style.display='none';els.latestEmpty.style.display='block';return;}
  els.latestImage.src=ev.mediaUrl;els.latestImage.style.display='block';els.latestEmpty.style.display='none';
}

function thumbHtml(ev){
  if(ev.type==='photo')return `<img src="${ev.mediaUrl}" alt="foto"><span class="media-badge photo-badge">📷</span>`;
  const imgTag=ev.thumb?`<img src="${ev.thumb}" alt="frame" id="vthumb_${ev.id}">`:`<div class="video-placeholder" id="vthumb_${ev.id}"><span class="spin">⏳</span></div>`;
  return `${imgTag}<span class="media-badge video-badge">🎬</span>`;
}

function renderHistory(){
  const groups=groupEvents(state.allEvents);
  els.historyGroups.innerHTML=groups.map(g=>`
    <section class="hour-group">
      <div class="hour-title">${g.label}</div>
      <div class="event-list">
        ${g.items.map(ev=>`
          <article class="event-card">
            <div class="event-thumb">${thumbHtml(ev)}</div>
            <div class="event-main">
              <div class="event-row1"><span class="event-time">${formatTime(ev.timestamp)}</span></div>
              <div class="event-date">${formatDate(ev.timestamp)}</div>
            </div>
            <div class="event-actions">
              <button class="icon-action-btn" data-open="${ev.id}" title="Ver">👁</button>
              <button class="icon-action-btn dl" data-download="${ev.id}" title="Descargar">📥</button>
            </div>
          </article>`).join('')}
      </div>
    </section>`).join('');
  document.querySelectorAll('[data-open]').forEach(b=>b.onclick=()=>openEvent(b.dataset.open));
  document.querySelectorAll('[data-download]').forEach(b=>b.onclick=()=>downloadEvent(b.dataset.download));
  els.btnLoadMore.style.display=state.pageToken?'inline-flex':'none';
}

function groupEvents(events){
  const groups=new Map();
  for(const ev of events){const d=new Date(ev.timestamp);const key=`${d.getFullYear()}-${d.getMonth()}-${d.getDate()}-${d.getHours()}`;if(!groups.has(key))groups.set(key,{label:formatHourLabel(ev.timestamp),items:[]});groups.get(key).items.push(ev);}
  return [...groups.values()];
}

function extractVideoFrame(blobUrl){
  return new Promise(resolve=>{
    const video=document.createElement('video'),canvas=document.createElement('canvas');
    video.muted=true;video.preload='metadata';video.src=blobUrl;
    video.addEventListener('loadedmetadata',()=>{video.currentTime=Math.min(1,video.duration*0.1);});
    video.addEventListener('seeked',()=>{canvas.width=video.videoWidth;canvas.height=video.videoHeight;canvas.getContext('2d').drawImage(video,0,0);video.src='';resolve(canvas.toDataURL('image/jpeg',0.7));});
    video.addEventListener('error',()=>resolve(null));setTimeout(()=>resolve(null),8000);
  });
}

async function loadVideoThumbnails(){
  const videos=state.allEvents.filter(ev=>ev.type==='video'&&!ev.thumb);
  for(const ev of videos){
    const frame=await extractVideoFrame(ev.mediaUrl);if(!frame)continue;
    ev.thumb=frame;const el=document.getElementById(`vthumb_${ev.id}`);
    if(el){const img=document.createElement('img');img.src=frame;img.alt='frame';img.id=`vthumb_${ev.id}`;el.replaceWith(img);}
  }
}

function openViewerHtml(html){els.viewerContent.innerHTML=html;openModal(els.viewerModal);}
function openEvent(id){const ev=state.allEvents.find(x=>x.id===id);if(!ev)return;if(ev.type==='photo')openViewerHtml(`<img src="${ev.mediaUrl}" alt="">`);else openViewerHtml(`<video src="${ev.mediaUrl}" controls autoplay playsinline></video>`);}
function downloadEvent(id){const ev=state.allEvents.find(x=>x.id===id);if(!ev)return;const a=document.createElement('a');a.href=ev.mediaUrl;a.download=ev.fileName||'adjunto';a.target='_blank';document.body.appendChild(a);a.click();a.remove();}

/* ─── Gmail fetch (parallel + format=full) ─── */
async function fetchNextBatch(){
  if(!await ensureToken()){toast('Sesión expirada.');startLogin();return [];}
  const q=encodeURIComponent(els.gmailQuery.value.trim()||'has:attachment');
  const tokenParam=state.pageToken?`&pageToken=${encodeURIComponent(state.pageToken)}`:'';
  const msgRes=await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=${BATCH}&q=${q}${tokenParam}`,{headers:{Authorization:`Bearer ${state.accessToken}`}});
  const msgData=await msgRes.json();state.pageToken=msgData.nextPageToken||null;
  const ids=(msgData.messages||[]).map(x=>x.id);if(!ids.length)return [];
  const messages=await Promise.all(ids.map(id=>fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}?format=full`,{headers:{Authorization:`Bearer ${state.accessToken}`}}).then(r=>r.json())));
  const perMessage=await Promise.all(messages.map(async msg=>{
    const internalDate=msg.internalDate?new Date(Number(msg.internalDate)).toISOString():new Date().toISOString();
    const parts=findParts(msg.payload?.parts||[]);const evs=[];
    await Promise.all(parts.map(async p=>{
      const filename=p.filename||'',mimeType=p.mimeType||'';
      const type=guessType(filename,mimeType);if(!type)return;
      const fileName=filename||(type==='photo'?'foto':'video');
      let rawData=null,mediaUrl='';
      if(p.body?.attachmentId){const att=await fetchAttachment(msg.id,p.body.attachmentId);if(att.data){rawData=att.data;mediaUrl=bytesToBlobUrl(base64UrlToUint8Array(att.data),mimeType);}}
      else if(p.body?.data){rawData=p.body.data;mediaUrl=bytesToBlobUrl(base64UrlToUint8Array(p.body.data),mimeType);}
      if(!mediaUrl||!rawData)return;
      evs.push({id:`${msg.id}_${fileName}`,messageId:msg.id,type,timestamp:internalDate,fileName,mimeType,data:rawData,mediaUrl,thumb:type==='photo'?mediaUrl:null});
    }));
    return evs;
  }));
  return perMessage.flat().sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
}

/* ─── loadHistory ─── */
async function loadHistory(){
  if(!state.gmailReady){toast('Aún no autenticado.');return;}
  els.gmailStatus.textContent='Cargando...';els.btnLoadHistory.disabled=true;state.pageToken=null;
  let cachedIds=new Set();
  try{
    const rows=await idbGetAll();
    if(rows.length){
      const events=rows.map(cacheRowToEvent).filter(Boolean).sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
      state.allEvents=events;state.latest=events.find(x=>x.type==='photo')||events[0]||null;
      cachedIds=new Set(events.map(x=>x.id));renderLatest();renderHistory();
      els.gmailStatus.textContent=`Caché: ${events.length} alertas`;
    }
  }catch(e){console.warn('IDB:',e);}
  try{
    const fresh=await fetchNextBatch();const trulyNew=fresh.filter(ev=>!cachedIds.has(ev.id));
    if(trulyNew.length){
      await idbSaveMany(trulyNew.map(eventToCacheRow));await idbPrune();
      state.allEvents=[...trulyNew,...state.allEvents].sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
      state.latest=state.allEvents.find(x=>x.type==='photo')||state.allEvents[0]||null;
      renderLatest();renderHistory();toast(`${trulyNew.length} alertas nuevas`);
    } else if(!cachedIds.size){
      state.allEvents=fresh;state.latest=fresh.find(x=>x.type==='photo')||fresh[0]||null;
      renderLatest();renderHistory();await idbSaveMany(fresh.map(eventToCacheRow));
      toast(`${fresh.length} alertas cargadas.`);
    }
    els.gmailStatus.textContent=`${state.allEvents.length} alertas`;
  }catch(e){els.gmailStatus.textContent=state.allEvents.length?`Caché: ${state.allEvents.length}`:'Error';if(!state.allEvents.length)toast('Error: '+e.message);}
  finally{els.btnLoadHistory.disabled=false;loadVideoThumbnails();}
}

async function loadMore(){
  if(!state.pageToken){toast('No hay más correos.');return;}
  els.gmailStatus.textContent='Cargando más...';els.btnLoadMore.disabled=true;
  try{
    const newEvents=await fetchNextBatch();
    if(newEvents.length){await idbSaveMany(newEvents.map(eventToCacheRow));await idbPrune();state.allEvents=[...state.allEvents,...newEvents].sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));renderHistory();toast(`${newEvents.length} alertas más.`);}
    els.gmailStatus.textContent=`${state.allEvents.length} alertas`;
    if(!state.pageToken)toast('No hay más correos.');
    loadVideoThumbnails();
  }catch(e){toast('Error: '+e.message);}finally{els.btnLoadMore.disabled=false;}
}

async function clearCache(){
  try{await idbClear();state.allEvents=[];state.latest=null;state.pageToken=null;renderLatest();renderHistory();els.gmailStatus.textContent='Caché borrada';toast('Caché eliminada.');}
  catch(e){toast('Error: '+e.message);}
}

function saveConfig(){cfg.allowedEmail=els.allowedEmail.value.trim();toast('Guardado.');closeModal(els.configModal);}

/* ─── Bindings ─── */
function bind(){
  updateClock();setInterval(updateClock,1000);
  els.btnGmail.onclick=()=>openModal(els.gmailModal);
  els.btnArm.onclick=()=>openModal(els.alarmModal);
  els.btnEye.onclick=()=>openModal(els.eyeModal);
  els.btnConfig.onclick=()=>openModal(els.configModal);
  document.querySelectorAll('[data-close]').forEach(b=>b.onclick=()=>closeModal(document.getElementById(b.dataset.close)));
  document.querySelectorAll('.overlay').forEach(ov=>ov.addEventListener('click',e=>{if(e.target===ov)closeModal(ov);}));
  els.btnGmailConnect.onclick=startLogin;
  els.btnLoadHistory.onclick=loadHistory;
  els.btnClearCache.onclick=clearCache;
  els.btnArmOn.onclick=()=>toggleArm(true);
  els.btnArmOff.onclick=()=>toggleArm(false);
  els.btnSaveConfig.onclick=saveConfig;
  els.btnLoadMore.onclick=loadMore;
  els.btnOpenLatest.onclick=()=>state.latest&&openEvent(state.latest.id);
  els.btnDownloadLatest.onclick=()=>state.latest&&downloadEvent(state.latest.id);
}

async function init(){
  els.gmailQuery.value=cfg.gmailQuery||'has:attachment';
  els.allowedEmail.value=cfg.allowedEmail||'';
  bind();toggleArm(false);renderLatest();renderHistory();
  await initAuth();
}
init();
