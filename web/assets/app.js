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

// Accessibility improvements
function announceToScreenReader(message) {
  const announcement = document.createElement('div');
  announcement.setAttribute('aria-live', 'polite');
  announcement.setAttribute('aria-atomic', 'true');
  announcement.className = 'sr-only';
  announcement.textContent = message;
  document.body.appendChild(announcement);

  // Remove after announcement
  setTimeout(() => {
    document.body.removeChild(announcement);
  }, 1000);
}

function setLoadingState(element, isLoading = true) {
  if (!element) {
    return;
  }

  if (isLoading) {
    element.setAttribute('aria-busy', 'true');
    element.classList.add('loading');
  } else {
    element.removeAttribute('aria-busy');
    element.classList.remove('loading');
  }
}

function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  notification.setAttribute('role', 'alert');
  notification.setAttribute('aria-live', 'assertive');
  notification.className = `notification notification-${type}`;
  notification.textContent = message;

  const styles = {
    position: 'fixed',
    top: '20px',
    right: '20px',
    padding: '12px 16px',
    borderRadius: '8px',
    color: 'white',
    fontSize: '14px',
    zIndex: '1000',
    maxWidth: '300px',
    wordWrap: 'break-word',
    boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
    opacity: '0',
    transform: 'translateY(-10px)',
    transition: 'all 0.3s ease',
  };

  Object.assign(notification.style, styles);

  switch (type) {
  case 'success':
    notification.style.background = 'linear-gradient(135deg, #71ffa0, #4ecdc4)';
    break;
  case 'error':
    notification.style.background = 'linear-gradient(135deg, #ff6b6b, #ee5a52)';
    break;
  case 'warning':
    notification.style.background = 'linear-gradient(135deg, #ffb870, #f39c12)';
    break;
  default:
    notification.style.background = 'linear-gradient(135deg, #00e5ff, #21ffa1)';
  }

  document.body.appendChild(notification);

  // Animate in
  requestAnimationFrame(() => {
    notification.style.opacity = '1';
    notification.style.transform = 'translateY(0)';
  });

  // Auto remove after 5 seconds
  setTimeout(() => {
    notification.style.opacity = '0';
    notification.style.transform = 'translateY(-10px)';
    setTimeout(() => {
      if (notification.parentNode) {
        document.body.removeChild(notification);
      }
    }, 300);
  }, 5000);

  // Allow manual dismiss on click
  notification.addEventListener('click', () => {
    notification.style.opacity = '0';
    notification.style.transform = 'translateY(-10px)';
    setTimeout(() => {
      if (notification.parentNode) {
        document.body.removeChild(notification);
      }
    }, 300);
  });
}

// Robust clipboard helper: tries navigator.clipboard in secure contexts,
// falls back to a hidden textarea + execCommand('copy') for HTTP or older browsers.
async function copyTextToClipboard(text) {
  if (!text && text !== '') {
    throw new Error('No text to copy');
  }
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      showNotification('Copied to clipboard!', 'success');
      announceToScreenReader('Text copied to clipboard');
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
  ta.setAttribute('aria-hidden', 'true');
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
      ok = true;
    } catch {
      showNotification('Copy failed - please copy manually', 'error');
      return false;
    }
  }

  if (ok) {
    showNotification('Copied to clipboard!', 'success');
    announceToScreenReader('Text copied to clipboard');
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
    showNotification(`Failed to load ${path.replace(/^\//, '')}`, 'error');
    return null;
  }
}

// Remove old error handling code that was left behind
// The new showNotification function handles all error display

function setOnline(isOnline) {
  statusDot.classList.toggle('offline', !isOnline);
  statusText.textContent = isOnline ? 'Online' : 'Offline';

  if (!isOnline) {
    showNotification('Server is offline or unreachable', 'error');
    announceToScreenReader('Server connection lost');
  }
}

function formatDate(ts) {
  if (!ts) {
    return '—';
  }
  try {
    const date = new Date(ts);
    return isNaN(date.getTime()) ? String(ts) : date.toLocaleString();
  } catch {
    return String(ts);
  }
}

async function loadStatus() {
  setLoadingState(quickStats, true);
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

    const meta = document.createElement('div');
    meta.className = 'meta';

    const channelsRow = document.createElement('div');
    channelsRow.appendChild(document.createTextNode('Channels: '));
    const channelsStrong = document.createElement('strong');
    channelsStrong.textContent = String(data.channel_count ?? '—');
    channelsRow.appendChild(channelsStrong);
    meta.appendChild(channelsRow);

    const scheduleRow = document.createElement('div');
    scheduleRow.appendChild(document.createTextNode('Schedule: '));
    const scheduleCode = document.createElement('code');
    scheduleCode.textContent = String(data.cron ?? '—');
    scheduleRow.appendChild(scheduleCode);
    meta.appendChild(scheduleRow);

    const cliRow = document.createElement('div');
    cliRow.appendChild(document.createTextNode('CLI version: '));
    const cliCode = document.createElement('code');
    cliCode.textContent = String(data.cli_version ?? '—');
    cliRow.appendChild(cliCode);
    meta.appendChild(cliRow);

    const streamRow = document.createElement('div');
    streamRow.appendChild(document.createTextNode('Stream endpoints: '));
    const streamCode = document.createElement('code');
    streamCode.textContent = streamEndpoints;
    streamRow.appendChild(streamCode);
    meta.appendChild(streamRow);

    quickStats.replaceChildren(meta);

    announceToScreenReader(`Status updated. ${data.channel_count || 0} channels available.`);
  } catch (error) {
    console.error('Status load failed:', error);
    setOnline(false);
  } finally {
    setLoadingState(quickStats, false);
  }
}

async function loadChannels() {
  setLoadingState(channelsEl, true);
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
      row.setAttribute('role', 'listitem');
      const channelNumber = document.createElement('div');
      channelNumber.className = 'ch';
      channelNumber.textContent = String(c.number ?? '—');
      row.appendChild(channelNumber);

      const channelName = document.createElement('div');
      channelName.className = 'name';
      channelName.textContent = String(c.name ?? '');
      channelName.title = String(c.name ?? '');
      row.appendChild(channelName);

      const channelBadge = document.createElement('div');
      channelBadge.className = 'badge';
      channelBadge.textContent = String(c.id ?? 'ta');
      row.appendChild(channelBadge);
      channelsEl.appendChild(row);
    });

    announceToScreenReader(`${list.length} channels loaded`);
    console.log(`Loaded ${list.length} channels`);
  } catch (error) {
    console.error('Channel load failed:', error);
    channelsEl.innerHTML =
      '<div class="row"><div class="ch">—</div><div class="name">Error loading channels</div><div></div></div>';
  } finally {
    setLoadingState(channelsEl, false);
  }
}

// Enhanced refresh with user feedback and accessibility
byId('refresh').addEventListener('click', async event => {
  const btn = event.target;
  const originalText = btn.textContent;

  try {
    btn.innerHTML = '<span aria-hidden="true">↻</span> Refreshing...';
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    setLoadingState(btn, true);

    const r = await fetch('/refresh', { method: 'POST' });
    if (r.ok) {
      await Promise.all([loadStatus(), loadChannels()]);
      btn.innerHTML = '<span aria-hidden="true">✓</span> Refreshed!';
      announceToScreenReader('Data refreshed successfully');
      setTimeout(() => {
        btn.innerHTML = originalText;
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
        setLoadingState(btn, false);
      }, 2000);
    } else {
      throw new Error(`HTTP ${r.status}`);
    }
  } catch (e) {
    console.warn('Refresh failed', e);
    showNotification('Refresh failed - please try again', 'error');
    btn.innerHTML = originalText;
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    setLoadingState(btn, false);
  }
});

// Load Xtreme Codes credentials with loading states
async function loadCredentials() {
  setLoadingState(xtremeUser, true);
  setLoadingState(xtremePass, true);

  try {
    const data = await fetchJSON('/credentials');
    if (data) {
      // Remove loading indicators and set actual content
      const userLoadingSpan = xtremeUser.querySelector('.loading-indicator');
      const passLoadingSpan = xtremePass.querySelector('.loading-indicator');

      if (userLoadingSpan) {
        userLoadingSpan.remove();
      }
      if (passLoadingSpan) {
        passLoadingSpan.remove();
      }

      xtremeUser.textContent = data.username;
      xtremePass.textContent = data.password;

      // Update direct URLs with credentials
      if (data.direct_urls) {
        const xtremeM3uUrl = byId('xtreme-m3u-url');
        const xtremeXmlUrl = byId('xtreme-xml-url');
        if (xtremeM3uUrl) {
          xtremeM3uUrl.textContent = data.direct_urls.xtreme_m3u;
        }
        if (xtremeXmlUrl) {
          xtremeXmlUrl.textContent = data.direct_urls.xtreme_xml;
        }
      }

      // Show creation info if available
      if (data.created_at) {
        const created = new Date(data.created_at).toLocaleDateString();
        const guideSummary = document.querySelector('.setup-guide summary');
        if (guideSummary) {
          guideSummary.textContent = `Popular IPTV Player Setup (Generated: ${created})`;
        }
      }

      announceToScreenReader('Credentials loaded successfully');
    }
  } catch (error) {
    console.error('Failed to load credentials:', error);
    xtremeUser.textContent = 'Error loading';
    xtremePass.textContent = 'Error loading';
  } finally {
    setLoadingState(xtremeUser, false);
    setLoadingState(xtremePass, false);
  }
}

// Load stream codes with improved loading states
async function loadStreamCodes() {
  console.log('Loading stream codes...');
  const container = byId('stream-codes-list');

  if (container) {
    setLoadingState(container, true);

    try {
      const data = await fetchJSON('/stream-codes');
      console.log('Stream codes data:', data);

      if (data?.stream_code_urls) {
        container.innerHTML = '';

        Object.entries(data.stream_code_urls).forEach(([code, url]) => {
          const div = document.createElement('div');
          div.className = 'url-item';

          const labelEl = document.createElement('label');
          labelEl.textContent = `${String(code).toUpperCase()}:`;
          div.appendChild(labelEl);

          const codeEl = document.createElement('code');
          codeEl.className = 'url-display';
          codeEl.setAttribute('aria-label', `Stream URL for ${String(code)}`);
          codeEl.textContent = String(url);
          div.appendChild(codeEl);

          const buttonEl = document.createElement('button');
          buttonEl.type = 'button';
          buttonEl.className = 'btn-sm copy-url';
          buttonEl.dataset.url = String(url);
          buttonEl.setAttribute('aria-label', `Copy ${String(code)} URL`);

          const iconSpan = document.createElement('span');
          iconSpan.setAttribute('aria-hidden', 'true');
          iconSpan.textContent = '📋';
          buttonEl.appendChild(iconSpan);
          buttonEl.appendChild(document.createTextNode(' Copy'));

          div.appendChild(buttonEl);
          container.appendChild(div);
        });

        // Add copy functionality to stream code URLs
        container.querySelectorAll('.copy-url').forEach(btn => {
          btn.addEventListener('click', async () => {
            const url = btn.dataset.url || '';
            const ok = await copyTextToClipboard(url);
            const prev = btn.innerHTML;
            btn.innerHTML = ok ? '<span aria-hidden="true">✓</span> Copied!' : '<span aria-hidden="true">⌗</span> Select+Copy';
            setTimeout(() => {
              btn.innerHTML = prev;
            }, 2000);
            if (!ok) {
              showNotification(
                'Clipboard access blocked by browser. Text shown in prompt for manual copy.',
                'error',
              );
            }
          });
        });

        announceToScreenReader(`${Object.keys(data.stream_code_urls).length} stream codes loaded`);
      } else {
        container.innerHTML = '<div class="url-item"><span class="url-label">No stream codes available</span></div>';
      }
    } catch (error) {
      console.error('Failed to load stream codes:', error);
      container.innerHTML = '<div class="url-item"><span class="url-label">Error loading stream codes</span></div>';
    } finally {
      setLoadingState(container, false);
    }
  }
}

// Enhanced tab switching with keyboard navigation and ARIA support
function switchTab(activeBtn) {
  // Update tab buttons
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('active');
    btn.setAttribute('aria-selected', 'false');
    btn.setAttribute('tabindex', '-1');
  });

  // Update tab content
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.add('hidden');
  });

  // Activate selected tab
  activeBtn.classList.add('active');
  activeBtn.setAttribute('aria-selected', 'true');
  activeBtn.setAttribute('tabindex', '0');

  const targetTab = byId('tab-' + activeBtn.dataset.tab);
  if (targetTab) {
    targetTab.classList.remove('hidden');
  }

  announceToScreenReader(`Switched to ${activeBtn.textContent} tab`);
}

document.querySelectorAll('.tab-btn').forEach((btn, index) => {
  btn.addEventListener('click', () => {
    switchTab(btn);
  });

  btn.addEventListener('keydown', (e) => {
    const tabs = Array.from(document.querySelectorAll('.tab-btn'));
    let newIndex = index;

    switch (e.key) {
    case 'ArrowLeft':
    case 'ArrowUp':
      e.preventDefault();
      newIndex = index > 0 ? index - 1 : tabs.length - 1;
      break;
    case 'ArrowRight':
    case 'ArrowDown':
      e.preventDefault();
      newIndex = index < tabs.length - 1 ? index + 1 : 0;
      break;
    case 'Home':
      e.preventDefault();
      newIndex = 0;
      break;
    case 'End':
      e.preventDefault();
      newIndex = tabs.length - 1;
      break;
    case 'Enter':
    case ' ':
      e.preventDefault();
      switchTab(btn);
      return;
    }

    if (newIndex !== index) {
      tabs[newIndex].focus();
      switchTab(tabs[newIndex]);
    }
  });
});

// Copy credentials button with improved accessibility
const copyBtn = byId('copy-xtreme');
if (copyBtn) {
  copyBtn.addEventListener('click', async () => {
    const serverText = xtremeUrl ? xtremeUrl.textContent : origin;
    const userText = xtremeUser ? xtremeUser.textContent : '';
    const passText = xtremePass ? xtremePass.textContent : '';
    const text = `Server: ${serverText}\nUsername: ${userText}\nPassword: ${passText}`;
    const ok = await copyTextToClipboard(text);
    const prevHtml = copyBtn.innerHTML;
    copyBtn.innerHTML = ok ? '<span aria-hidden="true">✓</span> Copied!' : '<span aria-hidden="true">⌗</span> Select+Copy';
    setTimeout(() => {
      copyBtn.innerHTML = prevHtml;
    }, 2000);
    if (!ok) {
      showNotification(
        'Clipboard access blocked by browser. Text shown in prompt for manual copy.',
        'error',
      );
    }
  });
}

loadStatus();
loadChannels();
loadCredentials();
loadStreamCodes();
setInterval(loadStatus, 30000);

// Generic inline copy buttons for URL codes with improved accessibility
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
    if (!text) {
      return;
    }
    const ok = await copyTextToClipboard(text);
    const prev = btn.innerHTML;
    btn.innerHTML = ok ? '<span aria-hidden="true">✓</span> Copied!' : '<span aria-hidden="true">⌗</span> Select+Copy';
    setTimeout(() => {
      btn.innerHTML = prev;
    }, 2000);
    if (!ok) {
      showNotification(
        'Clipboard access blocked by browser. Text shown in prompt for manual copy.',
        'error',
      );
    }
  });
});

// Logo overlay fallback: if local PNG missing, swap to remote reference image
window.addEventListener('DOMContentLoaded', () => {
  const overlay = document.querySelector('.logo .logo-inc');
  if (!overlay) {
    return;
  }
  const img = new Image();
  img.onload = () => {
    /* local asset exists, nothing to do */
  };
  img.onerror = () => {
    overlay.src = 'https://i.imgur.com/y0aF3SA.png?1';
  };
  img.src = overlay.src;
});
