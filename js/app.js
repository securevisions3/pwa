
/* ─── Config ─── */
const cfg = window.SV_CONFIG || {};
const SCOPES = 'openid email https://www.googleapis.com/auth/gmail.readonly';
const BATCH       = 3;
const WORKER_URL  = 'https://securevision-register.icivil-jmr.workers.dev';
const REDIRECT_URI = (location.origin + location.pathname).replace(/\/?$/, '/');

/* ─── State ─── */
const state = {
  armed:        false,
  allEvents:    [],
  pageToken:    null,
  latest:       null,
  accessToken:  '',
  tokenExpiry:  0,       // epoch ms
  selectedEmail:'',
  gmailReady:   false,
};

/* ─── localStorage keys ─── */
const LS_REFRESH = 'sv_refresh_token';
const LS_EXPIRY  = 'sv_token_expiry';
const LS_ACCESS  = 'sv_access_token';

/* ─── DOM refs ─── */
const els = {
  date:              document.getElementById('clock-date'),
  time:              document.getElementById('clock-time'),
  btnGmail:          document.getElementById('btn-gmail'),
  btnArm:            document.getElementById('btn-arm'),
  btnEye:            document.getElementById('btn-eye'),
  btnConfig:         document.getElementById('btn-config'),
  latestImage:       document.getElementById('latest-image'),
  latestEmpty:       document.getElementById('latest-empty'),
  btnOpenLatest:     document.getElementById('btn-open-latest'),
  btnDownloadLatest: document.getElementById('btn-download-latest'),
  historyGroups:     document.getElementById('history-groups'),
  btnLoadMore:       document.getElementById('btn-load-more'),
  viewerModal:       document.getElementById('viewer-modal'),
  viewerContent:     document.getElementById('viewer-content'),
  gmailModal:        document.getElementById('gmail-modal'),
  alarmModal:        document.getElementById('alarm-modal'),
  eyeModal:          document.getElementById('eye-modal'),
  configModal:       document.getElementById('config-modal'),
  gmailAccount:      document.getElementById('gmail-account'),
  gmailStatus:       document.getElementById('gmail-status'),
  btnGmailConnect:   document.getElementById('btn-gmail-connect'),
  btnLoadHistory:    document.getElementById('btn-load-history'),
  gmailQuery:        document.getElementById('gmail-query'),
  alarmStatus:       document.getElementById('alarm-status'),
  btnArmOn:          document.getElementById('btn-arm-on'),
  btnArmOff:         document.getElementById('btn-arm-off'),
  allowedEmail:      document.getElementById('allowed-email'),
  btnSaveConfig:     document.getElementById('btn-save-config'),
};

/* ─── Helpers ─── */
function pad(v){ return String(v).padStart(2,'0'); }
function toast(msg){ const t=document.createElement('div'); t.className='toast'; t.textContent=msg; document.getElementById('toast-container').appendChild(t); setTimeout(()=>t.remove(),2600); }
function openModal(el){ el.classList.remove('hidden'); }
function closeModal(el){ el.classList.add('hidden'); }

function updateClock(){
  const now = new Date();
  els.date.textContent = `${pad(now.getDate())}-${pad(now.getMonth()+1)}-${now.getFullYear()}`;
  els.time.textContent = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}
function toggleArm(force){
  state.armed = typeof force==='boolean' ? force : !state.armed;
  els.btnArm.textContent = state.armed ? '🔔' : '🔕';
  els.btnArm.classList.toggle('armed', state.armed);
  els.alarmStatus.textContent = state.armed ? 'Armada' : 'Desarmada';
}
function formatHourLabel(dateIso){
  const d=new Date(dateIso), h=d.getHours();
  return `Hoy ${pad(h)}:00 - ${pad(h+1)}:00`;
}
function formatTime(dateIso){ const d=new Date(dateIso); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
function formatDate(dateIso){ const d=new Date(dateIso); return `${pad(d.getDate())}-${pad(d.getMonth()+1)}-${d.getFullYear()}`; }

/* ─── PKCE helpers ─── */
function randomBase64Url(len){
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
async function sha256Base64Url(str){
  const bytes = new TextEncoder().encode(str);
  const hash  = await crypto.subtle.digest('SHA-256', bytes);
  return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

/* ─── Token storage ─── */
function saveTokens(access, refresh, expiresIn){
  const expiry = Date.now() + (expiresIn - 60) * 1000; // 60s de margen
  state.accessToken = access;
  state.tokenExpiry = expiry;
  localStorage.setItem(LS_ACCESS,  access);
  localStorage.setItem(LS_EXPIRY,  String(expiry));
  if(refresh) localStorage.setItem(LS_REFRESH, refresh);
}
function loadStoredTokens(){
  state.accessToken = localStorage.getItem(LS_ACCESS)  || '';
  state.tokenExpiry = Number(localStorage.getItem(LS_EXPIRY) || 0);
}
function isTokenValid(){
  return !!state.accessToken && Date.now() < state.tokenExpiry;
}
function clearTokens(){
  state.accessToken=''; state.tokenExpiry=0;
  localStorage.removeItem(LS_ACCESS);
  localStorage.removeItem(LS_EXPIRY);
  localStorage.removeItem(LS_REFRESH);
}

/* ─── Auth: refresh silently via Worker ─── */
async function refreshAccessToken(){
  const rt = localStorage.getItem(LS_REFRESH);
  if(!rt) return false;
  try {
    const res  = await fetch(`${WORKER_URL}/sv-refresh`, {
      method:  'POST',
      headers: { 'Content-Type':'application/json' },
      body:    JSON.stringify({ refresh_token: rt }),
    });
    const data = await res.json();
    if(!res.ok || !data.access_token) return false;
    saveTokens(data.access_token, null, data.expires_in);
    return true;
  } catch { return false; }
}

/* ─── Auth: ensure we have a valid token (call before any API use) ─── */
async function ensureToken(){
  if(isTokenValid()) return true;
  return refreshAccessToken();
}

/* ─── Auth: PKCE login flow (redirects to Google) ─── */
async function startLogin(){
  const verifier   = randomBase64Url(64);
  const challenge  = await sha256Base64Url(verifier);
  sessionStorage.setItem('sv_pkce_verifier', verifier);

  const params = new URLSearchParams({
    response_type:         'code',
    client_id:             cfg.googleClientId,
    redirect_uri:          REDIRECT_URI,
    scope:                 SCOPES,
    access_type:           'offline',
    prompt:                'consent',   // fuerza refresh_token en primera auth
    code_challenge:        challenge,
    code_challenge_method: 'S256',
  });
  location.href = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

/* ─── Auth: handle redirect-back from Google ─── */
async function handleOAuthCallback(){
  const params   = new URLSearchParams(location.search);
  const code     = params.get('code');
  const error    = params.get('error');
  if(error){ toast('Login cancelado.'); return false; }
  if(!code) return false;

  // Limpiar ?code=... de la URL sin recargar
  history.replaceState({}, '', location.pathname);

  const verifier = sessionStorage.getItem('sv_pkce_verifier');
  sessionStorage.removeItem('sv_pkce_verifier');
  if(!verifier){ toast('Error PKCE: verifier no encontrado.'); return false; }

  els.gmailStatus.textContent = 'Obteniendo tokens...';
  try {
    const res  = await fetch(`${WORKER_URL}/sv-exchange`, {
      method:  'POST',
      headers: { 'Content-Type':'application/json' },
      body:    JSON.stringify({ code, code_verifier: verifier, redirect_uri: REDIRECT_URI }),
    });
    const data = await res.json();
    if(!res.ok || !data.access_token){ toast('Error al obtener token: ' + (data.error||'?')); return false; }
    saveTokens(data.access_token, data.refresh_token, data.expires_in);
    state._idToken = data.id_token || null;
    return true;
  } catch(e){ toast('Error red: ' + e.message); return false; }
}

/* ─── Profile check ─── */
function decodeIdToken(idToken){
  try {
    const payload = idToken.split('.')[1];
    const json = atob(payload.replace(/-/g,'+').replace(/_/g,'/'));
    return JSON.parse(json);
  } catch { return {}; }
}

async function fetchProfile(idToken){
  let email = '';
  if(idToken){
    const claims = decodeIdToken(idToken);
    email = claims.email || '';
  }
  // Fallback: llamar userinfo si no hay id_token
  if(!email){
    try {
      const res  = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${state.accessToken}` }
      });
      const data = await res.json();
      email = data.email || '';
    } catch {}
  }
  state.selectedEmail = email;
  els.gmailAccount.textContent = email || 'Sin cuenta';
  if((cfg.allowedEmail||'').trim() && email.toLowerCase() !== String(cfg.allowedEmail).trim().toLowerCase()){
    els.gmailStatus.textContent = 'Cuenta no permitida';
    toast('La cuenta no coincide con el email permitido.');
    clearTokens();
    return false;
  }
  state.gmailReady = true;
  els.gmailStatus.textContent = 'Cuenta validada';
  return true;
}

/* ─── Startup auth flow ─── */
async function initAuth(){
  // 1. ¿Venimos de callback de Google?
  if(location.search.includes('code=')){
    const ok = await handleOAuthCallback();
    if(!ok){ els.gmailStatus.textContent='Error en login'; return; }
    await fetchProfile(state._idToken || null);
    return;
  }

  // 2. Cargar tokens guardados en localStorage
  loadStoredTokens();

  // 3. ¿Token válido?
  if(isTokenValid()){
    await fetchProfile(null);
    return;
  }

  // 4. Intentar refresh silencioso
  els.gmailStatus.textContent = 'Renovando sesión...';
  const ok = await refreshAccessToken();
  if(ok){
    await fetchProfile(null);
    return;
  }

  // 5. Sin tokens → mostrar botón de login
  els.gmailStatus.textContent = 'Sin sesión. Pulsa Conectar.';
  els.btnGmailConnect.style.display = 'inline-flex';
}

/* ─── Gmail API helpers ─── */
function base64UrlToUint8Array(b64){
  const base64 = b64.replace(/-/g,'+').replace(/_/g,'/');
  const padded = base64 + '='.repeat((4-(base64.length%4))%4);
  const raw = atob(padded);
  const arr = new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++) arr[i]=raw.charCodeAt(i);
  return arr;
}
function bytesToBlobUrl(bytes, mime){
  return URL.createObjectURL(new Blob([bytes],{type:mime||'application/octet-stream'}));
}
function guessType(filename, mimeType){
  const n=(filename||'').toLowerCase(), m=(mimeType||'').toLowerCase();
  if(m.startsWith('image/')||/\.(jpg|jpeg|png|webp|gif)$/i.test(n)) return 'photo';
  if(m.startsWith('video/')||/\.(mp4|webm|mov|avi|mkv)$/i.test(n)) return 'video';
  return '';
}
async function fetchAttachment(messageId, attachmentId){
  const res = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/attachments/${attachmentId}`,
    { headers:{ Authorization:`Bearer ${state.accessToken}` } }
  );
  return res.json();
}
function findParts(parts, out=[]){
  for(const p of parts||[]){ if(p.parts?.length) findParts(p.parts,out); else out.push(p); }
  return out;
}

/* ─── Rendering ─── */
function renderLatest(){
  const ev = state.latest;
  if(!ev){ els.latestImage.style.display='none'; els.latestEmpty.style.display='block'; return; }
  els.latestImage.src = ev.mediaUrl;
  els.latestImage.style.display='block';
  els.latestEmpty.style.display='none';
}

function thumbHtml(ev){
  if(ev.type==='photo'){
    return `<img src="${ev.mediaUrl}" alt="foto">
            <span class="media-badge photo-badge">📷</span>`;
  }
  // video: placeholder mientras no hay thumb
  const imgTag = ev.thumb
    ? `<img src="${ev.thumb}" alt="frame" id="vthumb_${ev.id}">`
    : `<div class="video-placeholder" id="vthumb_${ev.id}"><span class="spin">⏳</span></div>`;
  return `${imgTag}<span class="media-badge video-badge">🎬</span>`;
}

function renderHistory(){
  const groups = groupEvents(state.allEvents);
  els.historyGroups.innerHTML = groups.map(group=>`
    <section class="hour-group">
      <div class="hour-title">${group.label}</div>
      <div class="event-list">
        ${group.items.map(ev=>`
          <article class="event-card">
            <div class="event-thumb">${thumbHtml(ev)}</div>
            <div class="event-main">
              <div class="event-row1">
                <span class="event-time">${formatTime(ev.timestamp)}</span>
              </div>
              <div class="event-date">${formatDate(ev.timestamp)}</div>
            </div>
            <div class="event-actions">
              <button class="small-btn" data-open="${ev.id}">Abrir</button>
              <button class="small-btn" data-download="${ev.id}">Descargar</button>
            </div>
          </article>`).join('')}
      </div>
    </section>`).join('');

  document.querySelectorAll('[data-open]').forEach(b=>b.onclick=()=>openEvent(b.dataset.open));
  document.querySelectorAll('[data-download]').forEach(b=>b.onclick=()=>downloadEvent(b.dataset.download));
  els.btnLoadMore.style.display = state.pageToken ? 'inline-flex' : 'none';
}

function groupEvents(events){
  const groups=new Map();
  for(const ev of events){
    const d=new Date(ev.timestamp);
    const key=`${d.getFullYear()}-${d.getMonth()}-${d.getDate()}-${d.getHours()}`;
    if(!groups.has(key)) groups.set(key,{label:formatHourLabel(ev.timestamp),items:[]});
    groups.get(key).items.push(ev);
  }
  return [...groups.values()];
}

/* ─── Video thumbnails in background ─── */
function extractVideoFrame(blobUrl){
  return new Promise(resolve=>{
    const video   = document.createElement('video');
    const canvas  = document.createElement('canvas');
    video.muted   = true;
    video.preload = 'metadata';
    video.src     = blobUrl;
    video.addEventListener('loadedmetadata',()=>{
      video.currentTime = Math.min(1, video.duration * 0.1);
    });
    video.addEventListener('seeked',()=>{
      canvas.width  = video.videoWidth;
      canvas.height = video.videoHeight;
      canvas.getContext('2d').drawImage(video,0,0);
      video.src=''; // liberar memoria
      resolve(canvas.toDataURL('image/jpeg',0.7));
    });
    video.addEventListener('error',()=>resolve(null));
    // timeout de seguridad
    setTimeout(()=>resolve(null), 8000);
  });
}

async function loadVideoThumbnails(){
  const videos = state.allEvents.filter(ev=>ev.type==='video'&&!ev.thumb);
  for(const ev of videos){
    const frame = await extractVideoFrame(ev.mediaUrl);
    if(!frame) continue;
    ev.thumb = frame;
    // Actualizar solo ese card en el DOM
    const el = document.getElementById(`vthumb_${ev.id}`);
    if(el){
      const img = document.createElement('img');
      img.src = frame;
      img.alt = 'frame';
      img.id  = `vthumb_${ev.id}`;
      el.replaceWith(img);
    }
  }
}

/* ─── Event viewer / download ─── */
function openViewerHtml(html){ els.viewerContent.innerHTML=html; openModal(els.viewerModal); }
function openEvent(id){
  const ev=state.allEvents.find(x=>x.id===id); if(!ev) return;
  if(ev.type==='photo') openViewerHtml(`<img src="${ev.mediaUrl}" alt="${ev.fileName||''}">`);
  else openViewerHtml(`<video src="${ev.mediaUrl}" controls autoplay playsinline></video>`);
}
function downloadEvent(id){
  const ev=state.allEvents.find(x=>x.id===id); if(!ev) return;
  const a=document.createElement('a');
  a.href=ev.mediaUrl; a.download=ev.fileName||'adjunto'; a.target='_blank';
  document.body.appendChild(a); a.click(); a.remove();
}

/* ─── Gmail fetch ─── */
async function fetchNextBatch(){
  if(!await ensureToken()){ toast('Sesión expirada. Reconectando...'); startLogin(); return []; }

  const q=encodeURIComponent(els.gmailQuery.value.trim()||'has:attachment');
  const tokenParam=state.pageToken?`&pageToken=${encodeURIComponent(state.pageToken)}`:'';
  const msgRes=await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=${BATCH}&q=${q}${tokenParam}`,
    { headers:{ Authorization:`Bearer ${state.accessToken}` } }
  );
  const msgData=await msgRes.json();
  state.pageToken=msgData.nextPageToken||null;

  const ids=(msgData.messages||[]).map(x=>x.id);
  if(!ids.length) return [];

  const messages=await Promise.all(ids.map(id=>
    fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}?format=full`,
      { headers:{ Authorization:`Bearer ${state.accessToken}` } }).then(r=>r.json())
  ));

  const perMessage=await Promise.all(messages.map(async msg=>{
    const internalDate=msg.internalDate
      ? new Date(Number(msg.internalDate)).toISOString() : new Date().toISOString();
    const parts=findParts(msg.payload?.parts||[]);
    const evs=[];
    await Promise.all(parts.map(async p=>{
      const filename=p.filename||'', mimeType=p.mimeType||'';
      const type=guessType(filename,mimeType);
      if(!type) return;
      const fileName=filename||(type==='photo'?'foto':'video');
      let mediaUrl='';
      if(p.body?.attachmentId){
        const att=await fetchAttachment(msg.id,p.body.attachmentId);
        if(att.data) mediaUrl=bytesToBlobUrl(base64UrlToUint8Array(att.data),mimeType);
      } else if(p.body?.data){
        mediaUrl=bytesToBlobUrl(base64UrlToUint8Array(p.body.data),mimeType);
      }
      if(!mediaUrl) return;
      evs.push({
        id:`${msg.id}_${fileName}`, messageId:msg.id, type,
        timestamp:internalDate, mediaUrl,
        thumb: type==='photo' ? mediaUrl : null,   // video: thumb se extrae luego
        fileName
      });
    }));
    return evs;
  }));

  return perMessage.flat().sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
}

async function loadHistory(){
  if(!state.gmailReady){ toast('Aún no autenticado.'); return; }
  els.gmailStatus.textContent='Cargando...';
  els.btnLoadHistory.disabled=true;
  state.allEvents=[]; state.pageToken=null; state.latest=null;
  renderLatest();
  try{
    const events=await fetchNextBatch();
    state.allEvents=events;
    state.latest=events.find(x=>x.type==='photo')||events[0]||null;
    renderLatest();
    renderHistory();
    els.gmailStatus.textContent=`Historial cargado: ${events.length}`;
    toast(`${events.length} alertas cargadas.`);
    loadVideoThumbnails(); // background, no await
  } catch(e){
    els.gmailStatus.textContent='Error al cargar';
    toast('Error: '+e.message);
  } finally { els.btnLoadHistory.disabled=false; }
}

async function loadMore(){
  if(!state.pageToken){ toast('No hay más correos.'); return; }
  els.gmailStatus.textContent='Cargando más...';
  els.btnLoadMore.disabled=true;
  try{
    const newEvents=await fetchNextBatch();
    state.allEvents=[...state.allEvents,...newEvents];
    renderHistory();
    els.gmailStatus.textContent=`Historial: ${state.allEvents.length}`;
    if(!state.pageToken) toast('No hay más correos.');
    else toast(`${newEvents.length} alertas más cargadas.`);
    loadVideoThumbnails(); // background, no await
  } catch(e){ toast('Error: '+e.message); }
  finally { els.btnLoadMore.disabled=false; }
}

function saveConfig(){
  cfg.allowedEmail=els.allowedEmail.value.trim();
  toast('Configuración guardada.'); closeModal(els.configModal);
}

/* ─── Bindings ─── */
function bind(){
  updateClock(); setInterval(updateClock,1000);

  els.btnGmail.onclick  = ()=>openModal(els.gmailModal);
  els.btnArm.onclick    = ()=>openModal(els.alarmModal);
  els.btnEye.onclick    = ()=>openModal(els.eyeModal);
  els.btnConfig.onclick = ()=>openModal(els.configModal);

  document.querySelectorAll('[data-close]').forEach(btn=>{
    btn.onclick=()=>closeModal(document.getElementById(btn.dataset.close));
  });
  document.querySelectorAll('.overlay').forEach(ov=>{
    ov.addEventListener('click',e=>{ if(e.target===ov) closeModal(ov); });
  });

  els.btnGmailConnect.onclick = startLogin;
  els.btnLoadHistory.onclick  = loadHistory;
  els.btnArmOn.onclick        = ()=>toggleArm(true);
  els.btnArmOff.onclick       = ()=>toggleArm(false);
  els.btnSaveConfig.onclick   = saveConfig;
  els.btnLoadMore.onclick     = loadMore;
  els.btnOpenLatest.onclick   = ()=>state.latest&&openEvent(state.latest.id);
  els.btnDownloadLatest.onclick=()=>state.latest&&downloadEvent(state.latest.id);
}

/* ─── Init ─── */
async function init(){
  els.gmailQuery.value   = cfg.gmailQuery||'has:attachment';
  els.allowedEmail.value = cfg.allowedEmail||'';
  bind();
  toggleArm(false);
  renderLatest();
  renderHistory();
  await initAuth();
}
init();
