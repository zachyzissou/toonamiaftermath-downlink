const byId = (id)=>document.getElementById(id);
const statusDot = byId('status-dot');
const statusText = byId('status-text');
const lastUpdate = byId('last-update');
const nextRun = byId('next-run');
const channelsEl = byId('channels');
const quickStats = byId('quick-stats');
const m3uUrl = byId('m3u-url');
const xmlUrl = byId('xml-url');
const xtremeUrl = byId('xtreme-url');
const xtremeUser = byId('xtreme-user');
const xtremePass = byId('xtreme-pass');

// Build absolute URLs for copy/paste
const origin = window.location.origin;
const host = window.location.host;
if (m3uUrl) m3uUrl.textContent = origin + '/m3u';
if (xmlUrl) xmlUrl.textContent = origin + '/xml';
if (xtremeUrl) xtremeUrl.textContent = origin;

async function fetchJSON(path){
  try{
    const r = await fetch(path, {cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    return await r.json();
  }catch(e){
    console.warn('Fetch failed', path, e);
    return null;
  }
}

function setOnline(isOnline){
  statusDot.classList.toggle('offline', !isOnline);
  statusText.textContent = isOnline ? 'Online' : 'Offline';
}

function formatDate(ts){
  if(!ts) return '—';
  try{ return new Date(ts).toLocaleString(); } catch { return String(ts); }
}

async function loadStatus(){
  const data = await fetchJSON('/status');
  if(!data){ setOnline(false); return; }
  setOnline(true);
  lastUpdate.textContent = formatDate(data.last_update);
  nextRun.textContent = data.next_run ? formatDate(data.next_run) : '—';
  const streamEndpoints = data.stream_endpoints_available ? '✓ Available' : 'Not available';
  quickStats.innerHTML = `
    <div class="meta">
      <div>Channels: <strong>${data.channel_count ?? '—'}</strong></div>
      <div>Schedule: <code>${data.cron ?? '—'}</code></div>
      <div>CLI version: <code>${data.cli_version ?? '—'}</code></div>
      <div>Stream endpoints: <code>${streamEndpoints}</code></div>
    </div>`;
}

async function loadChannels(){
  const list = await fetchJSON('/channels');
  if(!list){ channelsEl.innerHTML = '<div class="row"><div class="ch">—</div><div class="name">Unable to load channels</div><div></div></div>'; return; }
  channelsEl.innerHTML = '';
  list.forEach((c)=>{
    const row = document.createElement('div');
    row.className = 'row';
    row.innerHTML = `
      <div class="ch">${c.number ?? '—'}</div>
      <div class="name" title="${c.name}">${c.name}</div>
      <div class="badge">${c.id ?? 'ta'}</div>`;
    channelsEl.appendChild(row);
  });
}

byId('refresh').addEventListener('click', async ()=>{
  try{
    const r = await fetch('/refresh', {method:'POST'});
    if(r.ok){ await Promise.all([loadStatus(), loadChannels()]); }
  }catch(e){ console.warn('Refresh failed', e); }
});

// Load Xtreme Codes credentials
async function loadCredentials(){
  const data = await fetchJSON('/credentials');
  if(data){
    xtremeUser.textContent = data.username;
    xtremePass.textContent = data.password;
    
    // Update direct URLs with credentials
    if(data.direct_urls) {
      const xtremeM3uUrl = byId('xtreme-m3u-url');
      const xtremeXmlUrl = byId('xtreme-xml-url');
      if(xtremeM3uUrl) xtremeM3uUrl.textContent = data.direct_urls.xtreme_m3u;
      if(xtremeXmlUrl) xtremeXmlUrl.textContent = data.direct_urls.xtreme_xml;
    }
    
    // Show creation info if available
    if(data.created_at) {
      const created = new Date(data.created_at).toLocaleDateString();
      const guideSummary = document.querySelector('.setup-guide summary');
      if (guideSummary) {
        guideSummary.textContent = `Popular IPTV Player Setup (Generated: ${created})`;
      }
    }
  }
}

// Load stream codes
async function loadStreamCodes(){
  console.log('Loading stream codes...');
  const data = await fetchJSON('/stream-codes');
  console.log('Stream codes data:', data);
  if(data && data.stream_code_urls){
    const container = byId('stream-codes-list');
    if(container) {
      container.innerHTML = '';
      Object.entries(data.stream_code_urls).forEach(([code, url]) => {
        const div = document.createElement('div');
        div.className = 'url-item';
        div.innerHTML = `
          <label>${code.toUpperCase()}:</label>
          <code class="url-display">${url}</code>
          <button type="button" class="btn-sm copy-url" data-url="${url}">📋 Copy</button>
        `;
        container.appendChild(div);
      });
      
      // Add copy functionality to stream code URLs
      container.querySelectorAll('.copy-url').forEach(btn => {
        btn.addEventListener('click', async () => {
          const url = btn.dataset.url;
          try {
            await navigator.clipboard.writeText(url);
            btn.textContent = '✓ Copied!';
            setTimeout(() => { btn.textContent = '📋 Copy'; }, 2000);
          } catch(e) {
            console.warn('Copy failed', e);
          }
        });
      });
    }
  }
}

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
    btn.classList.add('active');
    byId('tab-' + btn.dataset.tab).classList.remove('hidden');
  });
});

// Copy credentials button
const copyBtn = byId('copy-xtreme');
if (copyBtn) {
  copyBtn.addEventListener('click', async () => {
    const serverText = xtremeUrl ? xtremeUrl.textContent : origin;
    const userText = xtremeUser ? xtremeUser.textContent : '';
    const passText = xtremePass ? xtremePass.textContent : '';
    const text = `Server: ${serverText}\nUsername: ${userText}\nPassword: ${passText}`;
    try {
      await navigator.clipboard.writeText(text);
      copyBtn.textContent = '✓ Copied!';
      setTimeout(() => { copyBtn.textContent = '📋 Copy credentials'; }, 2000);
    } catch(e) {
      console.warn('Copy failed', e);
    }
  });
}

loadStatus();
loadChannels();
loadCredentials();
loadStreamCodes();
setInterval(loadStatus, 30000);

// Generic inline copy buttons for URL codes
document.querySelectorAll('.copy-inline').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const targetId = btn.getAttribute('data-target');
    const el = targetId ? byId(targetId) : null;
    const text = el ? el.textContent : '';
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const prev = btn.textContent;
      btn.textContent = '✓ Copied!';
      setTimeout(() => { btn.textContent = prev; }, 2000);
    } catch (e) {
      console.warn('Copy failed', e);
    }
  });
});
