const byId = id => document.getElementById(id);
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

// Robust clipboard helper: tries navigator.clipboard in secure contexts,
// falls back to a hidden textarea + execCommand('copy') for HTTP or older browsers.
async function copyTextToClipboard(text) {
  if (!text && text !== '') {throw new Error('No text to copy');}
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) {
    console.debug('navigator.clipboard write failed, falling back', e);
  }
  // Fallback using a temporary textarea (works on HTTP and older browsers)
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '-1000px';
  ta.style.left = '-1000px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  let ok = false;
  try {
    if (
      document.queryCommandSupported &&
      document.queryCommandSupported('copy')
    ) {
      ok = document.execCommand('copy');
    }
  } catch (e) {
    console.debug('document.execCommand copy failed', e);
    ok = false;
  }
  document.body.removeChild(ta);
  if (!ok) {
    // As a last resort, show a prompt so users can copy manually
    try {
      window.prompt('Copy to clipboard: Ctrl+C, Enter', text);
    } catch {
      // Ignore prompt errors
    }
  }
  return ok;
}

// Build absolute URLs for copy/paste
const origin = window.location.origin;
if (m3uUrl) {
  m3uUrl.textContent = origin + '/m3u';
}
if (xmlUrl) {
  xmlUrl.textContent = origin + '/xml';
}
if (xtremeUrl) {
  xtremeUrl.textContent = origin;
}

async function fetchJSON(path) {
  try {
    const r = await fetch(path, { cache: 'no-store' });
    if (!r.ok) {
      console.error(`HTTP ${r.status} fetching ${path}`);
      throw new Error(`HTTP ${r.status}: ${r.statusText}`);
    }
    return await r.json();
  } catch (e) {
    console.warn('Fetch failed', path, e);
    showErrorMessage(`Failed to load ${path}`);
    return null;
  }
}

function showErrorMessage(message) {
  // Create or update error banner
  let banner = document.getElementById('error-banner');
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'error-banner';
    banner.style.cssText = `
      position: fixed; top: 10px; right: 10px; 
      background: linear-gradient(135deg, #ff6b6b, #ee5a52);
      color: white; padding: 12px 16px; border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3); z-index: 1000;
      max-width: 300px; font-size: 14px; opacity: 0;
      transition: opacity 0.3s ease;
    `;
    document.body.appendChild(banner);
  }

  banner.textContent = message;
  banner.style.opacity = '1';

  // Auto-hide after 5 seconds
  setTimeout(() => {
    if (banner) {banner.style.opacity = '0';}
  }, 5000);
}

function hideErrorMessage() {
  const banner = document.getElementById('error-banner');
  if (banner) {banner.style.opacity = '0';}
}

function setOnline(isOnline) {
  statusDot.classList.toggle('offline', !isOnline);
  statusText.textContent = isOnline ? 'Online' : 'Offline';

  if (isOnline) {
    hideErrorMessage();
  } else {
    showErrorMessage('Server is offline or unreachable');
  }
}

function formatDate(ts) {
  if (!ts) {return '—';}
  try {
    const date = new Date(ts);
    return isNaN(date.getTime()) ? String(ts) : date.toLocaleString();
  } catch {
    return String(ts);
  }
}

async function loadStatus() {
  try {
    const data = await fetchJSON('/status');
    if (!data) {
      setOnline(false);
      return;
    }

    setOnline(true);
    lastUpdate.textContent = formatDate(data.last_update);
    nextRun.textContent = data.next_run ? formatDate(data.next_run) : '—';
    const streamEndpoints = data.stream_endpoints_available
      ? '✓ Available'
      : 'Not available';

    quickStats.innerHTML = `
      <div class="meta">
        <div>Channels: <strong>${data.channel_count ?? '—'}</strong></div>
        <div>Schedule: <code>${data.cron ?? '—'}</code></div>
        <div>CLI version: <code>${data.cli_version ?? '—'}</code></div>
        <div>Stream endpoints: <code>${streamEndpoints}</code></div>
      </div>`;
  } catch (error) {
    console.error('Status load failed:', error);
    setOnline(false);
  }
}

async function loadChannels() {
  try {
    const list = await fetchJSON('/channels');
    if (!list) {
      channelsEl.innerHTML =
        '<div class="row"><div class="ch">—</div><div class="name">Unable to load channels</div><div></div></div>';
      return;
    }

    channelsEl.innerHTML = '';
    if (list.length === 0) {
      channelsEl.innerHTML =
        '<div class="row"><div class="ch">—</div><div class="name">No channels available</div><div></div></div>';
      return;
    }

    list.forEach(c => {
      const row = document.createElement('div');
      row.className = 'row';
      // Escape HTML to prevent XSS
      const safeName = (c.name || '').replace(/[<>&"]/g, match => {
        const entities = {
          '<': '&lt;',
          '>': '&gt;',
          '&': '&amp;',
          '"': '&quot;',
        };
        return entities[match];
      });
      row.innerHTML = `
        <div class="ch">${c.number ?? '—'}</div>
        <div class="name" title="${safeName}">${safeName}</div>
        <div class="badge">${c.id ?? 'ta'}</div>`;
      channelsEl.appendChild(row);
    });

    console.log(`Loaded ${list.length} channels`);
  } catch (error) {
    console.error('Channel load failed:', error);
    channelsEl.innerHTML =
      '<div class="row"><div class="ch">—</div><div class="name">Error loading channels</div><div></div></div>';
  }
}

// Enhanced refresh with user feedback
byId('refresh').addEventListener('click', async event => {
  const btn = event.target;
  const originalText = btn.textContent;

  try {
    btn.textContent = '↻ Refreshing...';
    btn.disabled = true;

    const r = await fetch('/refresh', { method: 'POST' });
    if (r.ok) {
      await Promise.all([loadStatus(), loadChannels()]);
      btn.textContent = '✓ Refreshed!';
      setTimeout(() => {
        btn.textContent = originalText;
        btn.disabled = false;
      }, 2000);
    } else {
      throw new Error(`HTTP ${r.status}`);
    }
  } catch (e) {
    console.warn('Refresh failed', e);
    showErrorMessage('Refresh failed - please try again');
    btn.textContent = originalText;
    btn.disabled = false;
  }
});

// Load Xtreme Codes credentials
async function loadCredentials() {
  const data = await fetchJSON('/credentials');
  if (data) {
    xtremeUser.textContent = data.username;
    xtremePass.textContent = data.password;

    // Update direct URLs with credentials
    if (data.direct_urls) {
      const xtremeM3uUrl = byId('xtreme-m3u-url');
      const xtremeXmlUrl = byId('xtreme-xml-url');
      if (xtremeM3uUrl) {xtremeM3uUrl.textContent = data.direct_urls.xtreme_m3u;}
      if (xtremeXmlUrl) {xtremeXmlUrl.textContent = data.direct_urls.xtreme_xml;}
    }

    // Show creation info if available
    if (data.created_at) {
      const created = new Date(data.created_at).toLocaleDateString();
      const guideSummary = document.querySelector('.setup-guide summary');
      if (guideSummary) {
        guideSummary.textContent = `Popular IPTV Player Setup (Generated: ${created})`;
      }
    }
  }
}

// Load stream codes
async function loadStreamCodes() {
  console.log('Loading stream codes...');
  const data = await fetchJSON('/stream-codes');
  console.log('Stream codes data:', data);
  if (data?.stream_code_urls) {
    const container = byId('stream-codes-list');
    if (container) {
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
          const url = btn.dataset.url || '';
          const ok = await copyTextToClipboard(url);
          const prev = btn.textContent;
          btn.textContent = ok ? '✓ Copied!' : '⌗ Select+Copy';
          setTimeout(() => {
            btn.textContent = prev;
          }, 2000);
          if (!ok) {
            showErrorMessage(
              'Clipboard access blocked by browser. Text shown in prompt for manual copy.',
            );
          }
        });
      });
    }
  }
}

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document
      .querySelectorAll('.tab-btn')
      .forEach(b => b.classList.remove('active'));
    document
      .querySelectorAll('.tab-content')
      .forEach(c => c.classList.add('hidden'));
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
    const ok = await copyTextToClipboard(text);
    copyBtn.textContent = ok ? '✓ Copied!' : '⌗ Select+Copy';
    setTimeout(() => {
      copyBtn.textContent = '📋 Copy credentials';
    }, 2000);
    if (!ok) {
      showErrorMessage(
        'Clipboard access blocked by browser. Text shown in prompt for manual copy.',
      );
    }
  });
}

loadStatus();
loadChannels();
loadCredentials();
loadStreamCodes();
setInterval(loadStatus, 30000);

// Generic inline copy buttons for URL codes
document.querySelectorAll('.copy-inline').forEach(btn => {
  btn.addEventListener('click', async () => {
    const targetId = btn.getAttribute('data-target');
    const directText = btn.getAttribute('data-text');
    const el = targetId ? byId(targetId) : null;
    let text = '';
    if (directText && directText.length) {
      text = directText;
    } else if (el && el.textContent) {
      text = el.textContent;
    }
    if (!text) {return;}
    const ok = await copyTextToClipboard(text);
    const prev = btn.textContent;
    btn.textContent = ok ? '✓ Copied!' : '⌗ Select+Copy';
    setTimeout(() => {
      btn.textContent = prev;
    }, 2000);
    if (!ok) {
      showErrorMessage(
        'Clipboard access blocked by browser. Text shown in prompt for manual copy.',
      );
    }
  });
});

// Logo overlay fallback: if local PNG missing, swap to remote reference image
window.addEventListener('DOMContentLoaded', () => {
  const overlay = document.querySelector('.logo .logo-inc');
  if (!overlay) {return;}
  const img = new Image();
  img.onload = () => {
    /* local asset exists, nothing to do */
  };
  img.onerror = () => {
    overlay.src = 'https://i.imgur.com/y0aF3SA.png?1';
  };
  img.src = overlay.src;
});
