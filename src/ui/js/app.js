/* AI SOC Platform console.
 * All data comes from the API (REST + WebSocket). Log content is attacker-controlled, so every
 * value is HTML-escaped before it is rendered.
 */
'use strict';

// ======================================================================= helpers
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const store = {
  get: (k, d = '') => { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage blocked */ } },
};
const num = (n) => (n === null || n === undefined || n === '' ? '—' : Number(n).toLocaleString());
const dt = (ts) => { if (!ts) return '—'; const d = new Date(ts); return isNaN(d) ? esc(ts) : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }); };
const tm = (ts) => { if (!ts) return '—'; const d = new Date(ts); return isNaN(d) ? esc(ts) : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); };
const ago = (ts) => {
  const s = Math.round((Date.now() - new Date(ts)) / 1000);
  if (isNaN(s)) return '—';
  if (s < 60) return `${Math.max(s, 0)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return dt(ts);
};
const cap = (s) => String(s || '').replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
const sev = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const badge = (s) => `<span class="badge ${esc(s)}">${esc(cap(s))}</span>`;
const SOURCE_NAMES = { host: 'This computer', file: 'Log files', upload: 'Imported', api: 'API', syslog: 'Syslog', kafka: 'Kafka', simulation: 'Simulation' };
const srcTag = (s) => `<span class="src-tag ${esc(s)}">${esc(SOURCE_NAMES[s] || s || 'unknown')}</span>`;
const ent = (v) => (v ? `<span class="ent" data-entity="${esc(v)}">${esc(v)}</span>` : '');
const entityLinks = (e) => ['src_ip', 'hostname', 'user', 'dst_ip'].filter((k) => typeof (e || {})[k] === 'string')
  .map((k) => `<span class="sub">${k === 'src_ip' ? 'src' : k === 'dst_ip' ? 'dst' : k}</span> ${ent(e[k])}`).join(' &nbsp;');
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

function toast(msg, isError = false) {
  const t = $('toast');
  t.textContent = msg;
  t.className = `toast show${isError ? ' err' : ''}`;
  clearTimeout(t._t);
  t._t = setTimeout(() => { t.className = 'toast'; }, 3800);
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (store.get('soc.apiKey')) headers['X-API-Key'] = store.get('soc.apiKey');
  if (store.get('soc.analyst')) headers['X-Analyst'] = store.get('soc.analyst');
  const res = await fetch(path, { ...options, headers: { ...headers, ...(options.headers || {}) } });
  let body = null;
  try { body = await res.json(); } catch { /* not JSON */ }
  if (!res.ok) {
    const d = body && body.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => x.msg).join('; ') : (d || `HTTP ${res.status}`));
  }
  return body;
}
const post = (path, body) => api(path, { method: 'POST', body: JSON.stringify(body || {}) });

// ======================================================================= state & navigation
const state = { page: 'overview', stats: null, offset: 0, limit: 50, paused: false, received: 0, charts: {}, playbooks: [] };
const TITLES = { overview: 'Overview', alerts: 'Alerts', investigate: 'Investigate', events: 'Events', intel: 'Threat intelligence',
  response: 'Response', detection: 'Detection', sources: 'Data sources', settings: 'Settings' };
const LOADERS = {};

function showPage(page) {
  state.page = page;
  document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.page === page));
  document.querySelectorAll('.page').forEach((p) => p.classList.toggle('active', p.id === `page-${page}`));
  $('pageTitle').textContent = TITLES[page];
  if (LOADERS[page]) LOADERS[page]();
}
$('nav').addEventListener('click', (e) => { const a = e.target.closest('a[data-page]'); if (a) showPage(a.dataset.page); });
document.addEventListener('click', (e) => {
  const g = e.target.closest('[data-goto]');
  if (g) { showPage(g.dataset.goto); return; }
  const en = e.target.closest('[data-entity]');
  if (en) { e.stopPropagation(); $('drawer').classList.remove('open'); investigate(en.dataset.entity); return; }
  const al = e.target.closest('[data-alert]');
  if (al) openAlert(al.dataset.alert);
}, true);
$('globalSearch').addEventListener('submit', (e) => { e.preventDefault(); const v = $('globalSearchInput').value.trim(); if (v) investigate(v); });

// ======================================================================= theme
function applyTheme(choice) {
  const dark = choice === 'dark' || (choice === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  Object.values(state.charts).forEach((c) => c.destroy());
  state.charts = {};
  if (state.stats) renderOverview(state.stats);
}
$('themeBtn').addEventListener('click', () => {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  store.set('soc.theme', next);
  applyTheme(next);
});
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (store.get('soc.theme', 'auto') === 'auto') applyTheme('auto'); });

// ======================================================================= charts
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SOURCE_COLORS = { host: '#1f8a4c', file: '#2563eb', upload: '#7c3aed', api: '#0891b2', syslog: '#64748b', kafka: '#a16207', simulation: '#d97706' };

function chart(id, config) {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color = cssVar('--muted');
  Chart.defaults.borderColor = cssVar('--border');
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  if (state.charts[id]) { state.charts[id].data = config.data; state.charts[id].update('none'); return; }
  state.charts[id] = new Chart($(id), { ...config, options: { responsive: true, maintainAspectRatio: false, animation: false,
    plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, boxHeight: 10 } } }, ...config.options } });
}
const minuteLabel = (m) => new Date(`${m}:00Z`).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

// ======================================================================= overview
function renderOverview(s) {
  const a = s.alerts, open = a.open_by_severity || {};
  const events1h = Object.values(s.events_by_type_1h || {}).reduce((x, y) => x + y, 0);
  const kpis = [
    ['Open alerts', num(a.open), `${num(a.total)} total`, a.open ? 'warn' : ''],
    ['Critical & high', num((open.critical || 0) + (open.high || 0)), 'open, need attention', (open.critical || open.high) ? 'alert' : ''],
    ['Events (last hour)', num(events1h), `${s.ingestion.events_per_second} per second now`, ''],
    ['Awaiting approval', num(s.response.pending_approval), `response mode: ${s.response.mode === 'enforce' ? 'enforce' : 'dry run'}`, s.response.pending_approval ? 'warn' : ''],
    ['Blocked IPs', num(s.blocked_ips), '', ''],
    ['Detection latency', s.detection.latency_ms.p95 === null ? '—' : `${Number(s.detection.latency_ms.p95).toFixed(1)} ms`, 'p95 per event', ''],
  ];
  $('kpis').innerHTML = kpis.map(([l, v, sub, c]) => `<div class="kpi ${c}"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div><div class="sub">${esc(sub)}</div></div>`).join('');

  const tl = s.alert_timeline || [];
  chart('chartAlerts', {
    type: 'bar',
    data: { labels: tl.map((r) => minuteLabel(r.minute)),
      datasets: SEVERITIES.map((k) => ({ label: cap(k), data: tl.map((r) => r[k] || 0), backgroundColor: cssVar(`--${k}`), stack: 's', borderRadius: 2 })) },
    options: { scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } },
  });
  const vol = s.event_volume || [];
  const sources = [...new Set(vol.flatMap((r) => Object.keys(r).filter((k) => k !== 'minute')))];
  chart('chartVolume', {
    type: 'line',
    data: { labels: vol.map((r) => minuteLabel(r.minute)),
      datasets: sources.map((src) => ({ label: SOURCE_NAMES[src] || src, data: vol.map((r) => r[src] || 0), borderColor: SOURCE_COLORS[src] || '#64748b',
        backgroundColor: `${SOURCE_COLORS[src] || '#64748b'}22`, fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2 })) },
    options: { scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 } } } },
  });

  const maxSev = Math.max(1, ...SEVERITIES.map((k) => open[k] || 0));
  $('sevBars').innerHTML = SEVERITIES.map((k) => `<div class="bar-row"><span class="sev ${k}">${k}</span><div class="track"><div class="fill" style="width:${((open[k] || 0) / maxSev) * 100}%;background:var(--${k})"></div></div><span class="n">${num(open[k] || 0)}</span></div>`).join('');
  const cats = Object.entries(a.by_category || {}).sort((x, y) => y[1] - x[1]).slice(0, 6);
  const maxCat = Math.max(1, ...cats.map((c) => c[1]));
  $('catBars').innerHTML = cats.length ? cats.map(([c, n]) => `<div class="bar-row"><span>${esc(cap(c))}</span><div class="track"><div class="fill" style="width:${(n / maxCat) * 100}%;background:var(--accent)"></div></div><span class="n">${num(n)}</span></div>`).join('')
    : '<div class="hint">No alerts yet.</div>';

  const bySource = s.events_by_source_1h || {};
  const collectors = (s.ingestion.collectors || []).map((c) => c.type);
  const names = [...new Set([...collectors.map((t) => (t === 'file' ? 'file' : t)), ...Object.keys(bySource)])];
  $('sourceList').innerHTML = names.length ? names.map((src) => {
    const n = bySource[src] || 0;
    return `<div class="source-row"><span class="dot ${n ? 'ok' : 'info'}"></span><span class="name">${esc(SOURCE_NAMES[src] || src)}</span><span class="n">${num(n)} events / h</span></div>`;
  }).join('') : '<div class="hint">No data sources yet.</div>';

  $('topSources').innerHTML = (a.top_sources || []).length ? a.top_sources.map((t) => `<tr><td>${ent(t.ip)}</td><td class="num">${num(t.alerts)}</td></tr>`).join('')
    : '<tr><td colspan="2" class="empty">No alerting sources.</td></tr>';
}

function renderChrome(s) {
  const a = s.alerts;
  $('navAlerts').textContent = a.open || '';
  $('navPending').textContent = s.response.pending_approval || '';
  const enforce = s.response.mode === 'enforce';
  $('dotMode').className = `dot ${enforce ? 'bad' : 'info'}`;
  $('txtMode').textContent = enforce ? 'Response: ENFORCE' : 'Response: dry run';
  $('dotMl').className = `dot ${s.ml.ready ? 'ok' : 'warn'}`;
  $('txtMl').textContent = s.ml.ready ? 'ML model ready' : s.ml.training ? 'ML model training…' : 'ML model off';
  $('simBanner').hidden = !(s.simulation && s.simulation.running);
  $('lastUpdated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

async function loadRecentAlerts() {
  try {
    const { alerts } = await api('/api/v1/alerts?limit=8');
    $('recentAlerts').innerHTML = alerts.length ? alerts.map((a) => `<tr class="click" data-alert="${esc(a.id)}">
      <td>${sev(a.severity)}</td><td>${esc(a.rule_name)}</td><td>${entityLinks(a.entity)}</td><td class="num">${num(a.event_count)}</td>
      <td>${ago(a.last_seen)}</td><td>${badge(a.status)}</td></tr>`).join('')
      : '<tr><td colspan="6" class="empty">No alerts. Data from this computer, imported logs and other sources is being analysed.</td></tr>';
  } catch { /* handled by refresh */ }
}

async function refresh() {
  try {
    const s = await api('/api/v1/stats');
    state.stats = s;
    renderChrome(s);
    if (state.page === 'overview') { renderOverview(s); loadRecentAlerts(); }
    if (state.page === 'sources') renderSimulation(s.simulation);
  } catch (e) {
    if (/API-Key|401/.test(e.message)) toast('This server requires an API key - set it in Settings', true);
  }
}
LOADERS.overview = refresh;

// ======================================================================= alerts
async function loadAlerts() {
  const q = new URLSearchParams({ limit: state.limit, offset: state.offset });
  if ($('fSeverity').value) q.set('severity', $('fSeverity').value);
  if ($('fStatus').value) q.set('status', $('fStatus').value);
  if ($('fSearch').value.trim()) q.set('search', $('fSearch').value.trim());
  if ($('fOpen').checked) q.set('open_only', 'true');
  try {
    const { alerts, total } = await api(`/api/v1/alerts?${q}`);
    $('alertsCount').textContent = `${num(total)} alerts`;
    $('pageInfo').textContent = total ? `${state.offset + 1}–${Math.min(state.offset + state.limit, total)} of ${num(total)}` : '';
    $('prevPage').disabled = state.offset === 0;
    $('nextPage').disabled = state.offset + state.limit >= total;
    $('alertsTable').innerHTML = alerts.length ? alerts.map((a) => `<tr class="click" data-alert="${esc(a.id)}">
      <td><span class="prio ${esc(a.priority)}">${esc(a.priority)}</span></td><td>${sev(a.severity)}</td>
      <td>${esc(a.rule_name)}<div class="sub">${esc(a.id)}</div></td><td>${esc(cap(a.source))}<div class="sub">${esc(a.rule_id)}</div></td>
      <td>${entityLinks(a.entity)}</td><td class="num">${num(a.event_count)}</td><td class="num">${esc(a.score)}</td>
      <td>${ago(a.last_seen)}</td><td>${badge(a.status)}</td></tr>`).join('')
      : '<tr><td colspan="9" class="empty">No alerts match these filters.</td></tr>';
  } catch (e) { toast(e.message, true); }
}
LOADERS.alerts = loadAlerts;
['fSeverity', 'fStatus', 'fOpen'].forEach((id) => $(id).addEventListener('change', () => { state.offset = 0; loadAlerts(); }));
$('fSearch').addEventListener('keydown', (e) => { if (e.key === 'Enter') { state.offset = 0; loadAlerts(); } });
$('fRefresh').addEventListener('click', loadAlerts);
$('prevPage').addEventListener('click', () => { state.offset = Math.max(0, state.offset - state.limit); loadAlerts(); });
$('nextPage').addEventListener('click', () => { state.offset += state.limit; loadAlerts(); });

// ======================================================================= alert drawer
const kv = (rows) => `<div class="kv">${rows.filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => `<div>${esc(k)}</div><div>${v}</div>`).join('')}</div>`;

async function openAlert(id) {
  let a;
  try { a = await api(`/api/v1/alerts/${encodeURIComponent(id)}`); } catch (e) { toast(e.message, true); return; }
  const reasons = (a.evidence && a.evidence.reasons) || [];
  const evidence = { ...(a.evidence || {}) }; delete evidence.reasons;
  const mitre = (a.mitre || []).map((m) => `<a href="${esc(m.url)}" target="_blank" rel="noopener">${esc(m.id)}</a> ${esc(m.name)}`).join('<br>');
  const intel = (a.intel || []).map((i) => `<div class="note"><b>${esc(i.value)}</b> (${esc(i.type)}, matched in ${esc(i.field)})<br><span class="hint">${esc(i.source)} · confidence ${esc(i.confidence)}${i.description ? ` · ${esc(i.description)}` : ''}</span></div>`).join('');
  const responses = (a.responses || []).filter(Boolean).map((r) => `<div class="note">${esc(r.title)} ${badge(r.status)} <span class="hint">${dt(r.updated_at)}</span></div>`).join('');
  const notes = (a.notes || []).map((n) => `<div class="note"><span class="hint">${dt(n.at)} · ${esc(n.by)}</span><br>${esc(n.text)}</div>`).join('');
  const playbooks = state.playbooks.map((p) => {
    const suggested = (a.suggested_playbooks || []).includes(p.name);
    return `<button class="btn sm ${suggested ? 'primary' : ''}" data-run-playbook="${esc(p.name)}">${esc(p.title)}${suggested ? ' (suggested)' : ''}</button>`;
  }).join(' ');
  const samples = (a.sample_events || []).map((e) => `<tr><td>${tm(e['@timestamp'])}</td><td>${esc(e.event_type)}</td><td>${ent(e.src_ip)}</td><td>${ent(e.dst_ip)}${e.dst_port ? `:${esc(e.dst_port)}` : ''}</td><td class="sub">${esc(eventDetails(e))}</td></tr>`).join('');

  $('drawerContent').innerHTML = `
    <div class="row">${sev(a.severity)} <span class="prio ${esc(a.priority)}">${esc(a.priority)}</span> <span class="hint">Risk score ${esc(a.score)} · ${esc(cap(a.source))} detection${a.escalated ? ' · escalated' : ''}</span></div>
    <h2 class="title">${esc(a.rule_name)}</h2>
    <p class="hint">${esc(a.description)}</p>
    <div class="section">${kv([
      ['Status', badge(a.status)], ['Assigned to', esc(a.assignee || 'Unassigned')], ['Entity', entityLinks(a.entity)],
      ['Events', num(a.event_count)], ['First seen', dt(a.first_seen)], ['Last seen', dt(a.last_seen)],
      ['Rule', esc(a.rule_id)], ['MITRE ATT&CK', mitre || '—'], ['Alert ID', esc(a.id)],
    ])}</div>
    <div class="section"><h3>Triage</h3><div class="row">
      ${['investigating', 'contained', 'resolved', 'false_positive'].map((s) => `<button class="btn sm" data-set-status="${s}">${cap(s)}</button>`).join('')}
      <input id="assignInput" placeholder="Assign to" value="${esc(a.assignee || '')}" style="width:140px"><button class="btn sm" id="assignBtn">Assign</button></div></div>
    ${reasons.length ? `<div class="section"><h3>Why the model flagged it</h3>${reasons.map((r) => `<div class="note">${esc(r.text)}</div>`).join('')}</div>` : ''}
    ${intel ? `<div class="section"><h3>Threat intelligence matches</h3>${intel}</div>` : ''}
    <div class="section"><h3>Respond</h3><div class="row">${playbooks || '<span class="hint">No playbooks configured.</span>'}</div>${responses ? `<div class="mt">${responses}</div>` : ''}</div>
    <div class="section"><h3>Notes</h3>${notes || '<p class="hint">No notes yet.</p>'}
      <div class="row mt"><input id="noteInput" placeholder="Add a note" class="grow"><button class="btn sm" id="noteBtn">Add note</button></div></div>
    <div class="section"><h3>Events (${(a.sample_events || []).length} of ${num(a.event_count)})</h3>
      <table class="tbl"><thead><tr><th>Time</th><th>Type</th><th>From</th><th>To</th><th>Details</th></tr></thead><tbody>${samples}</tbody></table></div>
    <div class="section"><h3>Evidence</h3><pre class="json">${esc(JSON.stringify(evidence, null, 2))}</pre></div>`;
  $('drawer').dataset.current = a.id;
  $('drawer').classList.add('open');
}

async function patchAlert(body) {
  const id = $('drawer').dataset.current;
  try {
    await api(`/api/v1/alerts/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(body) });
    await openAlert(id);
    if (state.page === 'alerts') loadAlerts();
    refresh();
  } catch (e) { toast(e.message, true); }
}
$('drawerContent').addEventListener('click', async (e) => {
  const st = e.target.closest('[data-set-status]');
  if (st) return patchAlert({ status: st.dataset.setStatus });
  if (e.target.id === 'assignBtn') return patchAlert({ assignee: $('assignInput').value.trim() });
  if (e.target.id === 'noteBtn' && $('noteInput').value.trim()) return patchAlert({ note: $('noteInput').value.trim() });
  const pb = e.target.closest('[data-run-playbook]');
  if (pb) {
    try {
      const r = await post('/api/v1/responses', { playbook: pb.dataset.runPlaybook, alert_id: $('drawer').dataset.current });
      toast(r.status === 'pending_approval' ? `${r.title}: waiting for approval on the Response page` : `${r.title}: ${cap(r.status)}`);
      openAlert($('drawer').dataset.current);
    } catch (err) { toast(err.message, true); }
  }
});
$('drawerClose').addEventListener('click', () => $('drawer').classList.remove('open'));
$('drawer').addEventListener('click', (e) => { if (e.target.id === 'drawer') $('drawer').classList.remove('open'); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('drawer').classList.remove('open'); });

// ======================================================================= investigate
function investigate(value) {
  $('entityInput').value = value;
  showPage('investigate');
  loadEntity(value);
}
$('entityForm').addEventListener('submit', (e) => { e.preventDefault(); const v = $('entityInput').value.trim(); if (v) loadEntity(v); });

async function loadEntity(value) {
  $('entityResult').innerHTML = '<div class="empty-state">Loading…</div>';
  let d;
  try { d = await api(`/api/v1/entities/${encodeURIComponent(value)}`); } catch (e) { $('entityResult').innerHTML = `<div class="empty-state">${esc(e.message)}</div>`; return; }
  if (!d.events_total && !d.alerts.length && !d.intel) {
    $('entityResult').innerHTML = `<div class="empty-state">Nothing recorded for <b>${esc(value)}</b>.</div>`;
    return;
  }
  const isIp = /^[0-9a-f.:]+$/i.test(value) && /[.:]/.test(value);
  const types = Object.entries(d.by_type).map(([k, v]) => `<span class="badge">${esc(k)} ${num(v)}</span>`).join(' ');
  const actions = isIp ? `<button class="btn sm" data-entity-block="${esc(value)}">Block IP…</button> <button class="btn sm" data-entity-ioc="${esc(value)}">Add to threat intel</button>` : '';
  $('entityResult').innerHTML = `
    <div class="entity-head"><h2>${esc(value)}</h2>
      ${d.intel ? `<span class="badge failed">Known malicious · ${esc(d.intel.source)}</span>` : ''}
      ${d.blocked ? `<span class="badge dry_run">Blocked (${esc(cap(d.blocked.mode))})</span>` : ''}
      ${d.open_alerts ? `<span class="badge new">${d.open_alerts} open alerts</span>` : ''}
      <span class="spacer"></span>${actions}</div>
    <div class="kpis small">
      <div class="kpi"><div class="label">Events</div><div class="value">${num(d.events_total)}</div></div>
      <div class="kpi"><div class="label">Flagged events</div><div class="value">${num(d.flagged_events)}</div></div>
      <div class="kpi"><div class="label">Alerts</div><div class="value">${num(d.alerts.length)}</div></div>
      <div class="kpi"><div class="label">First seen</div><div class="value" style="font-size:14px">${dt(d.first_seen)}</div></div>
      <div class="kpi"><div class="label">Last seen</div><div class="value" style="font-size:14px">${dt(d.last_seen)}</div></div>
    </div>
    ${d.intel ? `<div class="note"><b>Threat intel:</b> ${esc(d.intel.description || '')} <span class="hint">(${esc(d.intel.source)}, confidence ${esc(d.intel.confidence)})</span></div>` : ''}
    <div class="row mt">${types}</div>
    <div class="grid g-3-2 mt">
      <div><h2 class="mt">Alerts</h2><table class="tbl"><thead><tr><th>Severity</th><th>Alert</th><th class="num">Events</th><th>Last seen</th><th>Status</th></tr></thead><tbody>
        ${d.alerts.length ? d.alerts.map((a) => `<tr class="click" data-alert="${esc(a.id)}"><td>${sev(a.severity)}</td><td>${esc(a.rule_name)}</td><td class="num">${num(a.event_count)}</td><td>${ago(a.last_seen)}</td><td>${badge(a.status)}</td></tr>`).join('') : '<tr><td colspan="5" class="empty">No alerts.</td></tr>'}
      </tbody></table></div>
      <div><h2 class="mt">Talks to</h2><table class="tbl"><thead><tr><th>Peer</th><th class="num">Events</th></tr></thead><tbody>
        ${d.top_peers.length ? d.top_peers.map((p) => `<tr><td>${ent(p.ip)}</td><td class="num">${num(p.events)}</td></tr>`).join('') : '<tr><td colspan="2" class="empty">—</td></tr>'}
      </tbody></table></div>
    </div>
    <h2 class="mt">Activity timeline <span class="hint">(latest ${d.events.length})</span></h2>
    <table class="tbl"><thead><tr><th>Time</th><th>Source</th><th>Type</th><th>From</th><th>To</th><th>Details</th></tr></thead><tbody>
      ${d.events.map((e) => `<tr${e.flagged ? ' style="background:var(--critical-soft)"' : ''}><td>${dt(e['@timestamp'])}</td><td>${srcTag(e.source_type)}</td><td>${esc(e.event_type)}</td><td>${ent(e.src_ip)}</td><td>${ent(e.dst_ip)}${e.dst_port ? `:${esc(e.dst_port)}` : ''}</td><td class="sub">${esc(eventDetails(e))}</td></tr>`).join('')}
    </tbody></table>`;
}
$('entityResult').addEventListener('click', async (e) => {
  const blk = e.target.closest('[data-entity-block]'), ioc = e.target.closest('[data-entity-ioc]');
  try {
    if (blk) { const r = await post('/api/v1/responses', { playbook: 'block_ip', target: { src_ip: blk.dataset.entityBlock } }); toast(`Block requested (${cap(r.status)})`); }
    if (ioc) { await post('/api/v1/intel/iocs', { value: ioc.dataset.entityIoc, description: 'Added from investigation' }); toast('Added to threat intel'); loadEntity(ioc.dataset.entityIoc); }
  } catch (err) { toast(err.message, true); }
});

// ======================================================================= events
function eventDetails(e) {
  const parts = [];
  for (const k of ['process_name', 'user', 'hostname', 'query', 'url', 'waf_signature', 'edr_verdict', 'status_code', 'bytes_out', 'local_port', 'message']) {
    if (e[k] !== undefined && e[k] !== null && e[k] !== '') parts.push(`${k.replace('_name', '')}=${String(e[k]).slice(0, 120)}`);
  }
  return parts.join('  ');
}
function addStreamEvent(e) {
  state.received += 1;
  if (state.paused) return;
  if ($('evFlagged').checked && !e.flagged) return;
  if ($('evSource').value && e.source_type !== $('evSource').value) return;
  const f = $('evFilter').value.trim().toLowerCase();
  const text = `${e.event_type} ${e.src_ip || ''} ${e.dst_ip || ''} ${eventDetails(e)}`;
  if (f && !text.toLowerCase().includes(f)) return;
  const box = $('eventStream');
  if (box.firstElementChild && box.firstElementChild.classList.contains('empty-state')) box.innerHTML = '';
  const row = document.createElement('div');
  row.className = `ev${e.flagged ? ' flag' : ''}`;
  row.innerHTML = `<span class="t">${tm(e['@timestamp'])}</span><span>${srcTag(e.source_type)}</span><span class="ty">${esc(e.event_type)}</span>
    <span class="d">${e.src_ip ? ent(e.src_ip) : ''}${e.dst_ip ? ` → ${ent(e.dst_ip)}${e.dst_port ? `:${esc(e.dst_port)}` : ''}` : ''}  ${esc(eventDetails(e))}</span>`;
  box.prepend(row);
  while (box.children.length > 400) box.lastChild.remove();
}
$('evPause').addEventListener('click', () => { state.paused = !state.paused; $('evPause').textContent = state.paused ? 'Resume' : 'Pause'; });
$('evClear').addEventListener('click', () => { $('eventStream').innerHTML = ''; });
async function searchEvents() {
  const q = new URLSearchParams({ limit: 150 });
  if ($('evSearch').value.trim()) q.set('search', $('evSearch').value.trim());
  try {
    const { events } = await api(`/api/v1/events?${q}`);
    $('evResults').innerHTML = events.length ? events.map((e) => `<tr${e.flagged ? ' style="background:var(--critical-soft)"' : ''}>
      <td>${dt(e['@timestamp'])}</td><td>${srcTag(e.source_type)}</td><td>${esc(e.event_type)}</td><td>${ent(e.src_ip)}</td>
      <td>${ent(e.dst_ip)}${e.dst_port ? `:${esc(e.dst_port)}` : ''}</td><td class="sub">${esc(eventDetails(e))}</td></tr>`).join('')
      : '<tr><td colspan="6" class="empty">No stored events match.</td></tr>';
  } catch (e) { toast(e.message, true); }
}
LOADERS.events = searchEvents;
$('evSearchForm').addEventListener('submit', (e) => { e.preventDefault(); searchEvents(); });

// ======================================================================= intel
async function loadIntel() {
  const q = new URLSearchParams({ limit: 500 });
  if ($('iocSearch').value.trim()) q.set('search', $('iocSearch').value.trim());
  if ($('iocFilterType').value) q.set('type', $('iocFilterType').value);
  try {
    const { iocs, total, stats } = await api(`/api/v1/intel/iocs?${q}`);
    const c = stats.counts;
    $('intelKpis').innerHTML = [['Indicators', stats.total], ['IP addresses', c.ip + c.cidr], ['Domains', c.domain], ['File hashes', c.hash], ['Matches in events', stats.hits]]
      .map(([l, v]) => `<div class="kpi"><div class="label">${esc(l)}</div><div class="value">${num(v)}</div></div>`).join('');
    $('iocTable').innerHTML = iocs.length ? iocs.map((i) => `<tr><td>${esc(i.type)}</td><td class="mono">${['ip', 'domain'].includes(i.type) ? ent(i.value) : esc(i.value)}</td>
      <td>${esc(i.source)}</td><td class="num">${esc(i.confidence)}</td><td class="sub">${esc(i.description || '')}</td>
      <td><button class="link" data-del-ioc="${esc(i.type)}|${esc(i.value)}">Remove</button></td></tr>`).join('')
      + (total > iocs.length ? `<tr><td colspan="6" class="empty">${num(total - iocs.length)} more - refine the search</td></tr>` : '')
      : '<tr><td colspan="6" class="empty">No indicators.</td></tr>';
    $('feeds').innerHTML = stats.feeds.length ? stats.feeds.map((f) => `<div class="source-row"><span class="dot ${f.enabled ? (f.last_error ? 'bad' : 'ok') : ''}"></span>
      <span class="name">${esc(f.name)}</span><span class="n">${f.enabled ? (f.last_update ? `${num(f.last_count)} indicators · ${ago(f.last_update)}` : 'enabled') : 'disabled'}${f.last_error ? ` · ${esc(f.last_error)}` : ''}</span></div>`).join('')
      + '<p class="hint mt">Enable public feeds (abuse.ch) in config/detection.yaml → intel.feeds.</p>'
      : '<p class="hint">No feeds configured.</p>';
  } catch (e) { toast(e.message, true); }
}
LOADERS.intel = loadIntel;
$('iocSearch').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadIntel(); });
$('iocFilterType').addEventListener('change', loadIntel);
$('iocForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const r = await post('/api/v1/intel/iocs', { value: $('iocValue').value.trim(), type: $('iocType').value || null, description: $('iocDesc').value.trim() });
    $('iocMsg').textContent = `Added ${r.type} ${r.value}`;
    $('iocValue').value = ''; $('iocDesc').value = '';
    loadIntel();
  } catch (err) { $('iocMsg').textContent = err.message; }
});
$('iocTable').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-del-ioc]');
  if (!b) return;
  const [type, ...rest] = b.dataset.delIoc.split('|');
  try { await api(`/api/v1/intel/iocs/${encodeURIComponent(type)}/${encodeURIComponent(rest.join('|'))}`, { method: 'DELETE' }); loadIntel(); }
  catch (err) { toast(err.message, true); }
});
$('lookupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const v = $('lookupValue').value.trim();
  if (!v) return;
  try {
    const r = await api(`/api/v1/intel/lookup?value=${encodeURIComponent(v)}`);
    const local = r.local ? `<div class="note"><span class="badge failed">Listed</span> ${esc(r.local.description || '')} <span class="hint">${esc(r.local.source)} · confidence ${esc(r.local.confidence)}</span></div>`
      : '<div class="note"><span class="badge done">Not in local threat intel</span></div>';
    const online = Object.keys(r.online || {}).length ? `<pre class="json">${esc(JSON.stringify(r.online, null, 2))}</pre>` : '';
    $('lookupResult').innerHTML = `<div class="hint">${esc(v)} · ${esc(r.type || 'unknown type')}</div>${local}${online}`;
  } catch (err) { $('lookupResult').textContent = err.message; }
});
$('feedsRefresh').addEventListener('click', async () => { try { await post('/api/v1/intel/refresh'); loadIntel(); toast('Feeds refreshed'); } catch (e) { toast(e.message, true); } });

// ======================================================================= response
async function loadPlaybooks() {
  try {
    const { playbooks } = await api('/api/v1/playbooks');
    state.playbooks = playbooks;
    if (!$('pbSelect').options.length) playbooks.forEach((p) => $('pbSelect').add(new Option(p.title, p.name)));
    $('pbList').innerHTML = playbooks.map((p) => `<div class="note"><b>${esc(p.title)}</b> ${p.requires_approval ? '<span class="badge">needs approval</span>' : ''}<br>
      <span class="hint">${esc(p.description)}</span></div>`).join('');
  } catch { /* shown elsewhere */ }
}
const target = (t) => Object.entries(t || {}).map(([k, v]) => `<span class="sub">${esc(k)}</span> ${ent(v)}`).join(' ');
const actionList = (r) => r.actions.map((a) => `<span class="badge ${esc(a.status)}" title="${esc(a.detail || a.error || '')}">${esc(cap(a.type))}</span>`).join(' ');
async function loadResponse() {
  await loadPlaybooks();
  try {
    const [pending, all, blocked] = await Promise.all([api('/api/v1/responses?status=pending_approval'), api('/api/v1/responses?limit=60'), api('/api/v1/blocked')]);
    const enforce = all.mode === 'enforce';
    $('modeBanner').className = `notice${enforce ? ' enforce' : ''}`;
    $('modeBanner').innerHTML = enforce
      ? '<b>Enforce mode.</b> Approved actions change firewall rules and call your EDR / identity webhooks.'
      : '<b>Dry-run mode.</b> Responses are planned, approved and audited, but nothing on your systems is changed. Set <code>mode: enforce</code> in config/response.yaml to act for real.';
    $('pendingTable').innerHTML = pending.responses.length ? pending.responses.map((r) => `<tr><td>${ago(r.created_at)}</td><td>${esc(r.title)}</td>
      <td>${target(r.target)}</td><td>${r.alert_id ? `<a data-alert="${esc(r.alert_id)}">${esc(r.alert_id)}</a>` : '—'}</td><td>${esc(r.requested_by)}</td><td>${actionList(r)}</td>
      <td class="num"><button class="btn sm primary" data-approve="${esc(r.id)}">Approve</button> <button class="btn sm" data-reject="${esc(r.id)}">Reject</button></td></tr>`).join('')
      : '<tr><td colspan="7" class="empty">Nothing is waiting for approval.</td></tr>';
    $('historyTable').innerHTML = all.responses.length ? all.responses.map((r) => `<tr><td>${dt(r.updated_at)}</td><td>${esc(r.title)}</td><td>${target(r.target)}</td>
      <td>${badge(r.status)}</td><td>${actionList(r)}</td><td>${esc(r.decided_by || r.requested_by || '')}</td></tr>`).join('')
      : '<tr><td colspan="6" class="empty">No responses yet.</td></tr>';
    $('blockedTable').innerHTML = blocked.blocked.length ? blocked.blocked.map((b) => `<tr><td>${ent(b.ip)}</td><td>${badge(b.mode)}</td><td>${ago(b.blocked_at)}</td>
      <td>${b.expires_at ? dt(b.expires_at) : 'never'}</td><td class="num"><button class="link" data-unblock="${esc(b.ip)}">Unblock</button></td></tr>`).join('')
      : `<tr><td colspan="5" class="empty">No blocked addresses · firewall: ${esc(blocked.backend)}</td></tr>`;
  } catch (e) { toast(e.message, true); }
}
LOADERS.response = loadResponse;
document.addEventListener('click', async (e) => {
  const ap = e.target.closest('[data-approve]'), rj = e.target.closest('[data-reject]'), ub = e.target.closest('[data-unblock]');
  if (!ap && !rj && !ub) return;
  try {
    if (ap) { const r = await post(`/api/v1/responses/${ap.dataset.approve}/approve`); toast(`${r.title}: ${cap(r.status)}`); }
    if (rj) { const reason = prompt('Reason for rejecting (optional)') ?? ''; await post(`/api/v1/responses/${rj.dataset.reject}/reject`, { reason }); }
    if (ub) { await api(`/api/v1/blocked/${encodeURIComponent(ub.dataset.unblock)}`, { method: 'DELETE' }); toast(`Unblocked ${ub.dataset.unblock}`); }
    loadResponse(); refresh();
  } catch (err) { toast(err.message, true); }
});
$('pbForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const t = {};
  if ($('pbIp').value.trim()) t.src_ip = $('pbIp').value.trim();
  if ($('pbHost').value.trim()) t.hostname = $('pbHost').value.trim();
  if ($('pbUser').value.trim()) t.user = $('pbUser').value.trim();
  try { const r = await post('/api/v1/responses', { playbook: $('pbSelect').value, target: t }); $('pbMsg').textContent = `${r.id}: ${cap(r.status)}`; loadResponse(); }
  catch (err) { $('pbMsg').textContent = err.message; }
});

// ======================================================================= detection
async function loadDetection() {
  try {
    const [rules, ml] = await Promise.all([api('/api/v1/rules'), api('/api/v1/ml')]);
    $('ruleStats').textContent = `${rules.stats.enabled_rules} of ${rules.stats.total_rules} enabled${rules.stats.rules_failed ? ` · ${rules.stats.rules_failed} failed to load` : ''}`;
    $('rulesTable').innerHTML = rules.rules.map((r) => `<tr><td><input type="checkbox" data-rule="${esc(r.rule_id)}" ${r.enabled ? 'checked' : ''}></td>
      <td>${esc(r.rule_name)}<div class="sub">${esc(r.rule_id)}${r.description ? ` · ${esc(r.description)}` : ''}</div></td>
      <td class="nw">${esc(cap(r.source))}</td><td class="nw">${sev(r.severity)}</td><td>${esc(cap(r.category))}</td>
      <td>${(r.mitre || []).map((m) => `<a href="https://attack.mitre.org/techniques/${esc(m.replace('.', '/'))}/" target="_blank" rel="noopener">${esc(m)}</a>`).join(' ')}</td><td class="num">${num(r.hits)}</td></tr>`).join('');
    $('chainTable').innerHTML = rules.chains.map((c) => `<tr><td>${esc(c.name)}<div class="sub">${esc(c.id)}</div></td><td class="num">${num(c.hits)}</td><td class="num">${num(c.tracking)}</td></tr>`).join('');
    const m = ml.model || {}, ev = m.evaluation || {}, drift = ml.drift || {};
    $('mlStatus').innerHTML = kv([
      ['Status', ml.ready ? '<span class="badge done">Ready</span>' : ml.training ? '<span class="badge investigating">Training…</span>' : '<span class="badge">Not trained</span>'],
      ['Model', esc(m.model || '—')], ['Learned from', esc(m.trained_on || '—')], ['Trained', dt(m.trained_at)],
      ['Training events', num(m.samples)], ['Events scored', num(ml.inferences)], ['Anomalous events', num(ml.anomalies)],
      ['Simulated test', ev.attack_scenarios ? `${Math.round(ev.scenarios_detected * 100)}% of ${ev.attack_scenarios} attacks flagged, ${ev.false_positive_sources} false-positive sources` : '—'],
      ['Score drift (PSI)', drift.psi === null || drift.psi === undefined ? esc(cap(drift.status || '—')) : `${drift.psi} (${esc(drift.status)})`],
      ['Error', esc(ml.last_error || '')],
    ]) + '<p class="hint mt">The model learns what normal looks like. Retrain it on your own recent events once the platform has seen a day or two of your normal traffic.</p>';
  } catch (e) { toast(e.message, true); }
}
LOADERS.detection = loadDetection;
$('rulesTable').addEventListener('change', async (e) => {
  const cb = e.target.closest('[data-rule]');
  if (!cb) return;
  try { await api(`/api/v1/rules/${encodeURIComponent(cb.dataset.rule)}`, { method: 'PATCH', body: JSON.stringify({ enabled: cb.checked }) }); toast(`${cb.dataset.rule} ${cb.checked ? 'enabled' : 'disabled'}`); }
  catch (err) { cb.checked = !cb.checked; toast(err.message, true); }
});
$('rulesReload').addEventListener('click', async () => { try { await post('/api/v1/rules/reload'); loadDetection(); toast('Rule files reloaded'); } catch (e) { toast(e.message, true); } });
async function retrain(source) {
  try { await post('/api/v1/ml/retrain', { source }); $('mlMsg').textContent = 'Training… detection keeps running and the new model is swapped in when ready.'; setTimeout(loadDetection, 4000); }
  catch (e) { $('mlMsg').textContent = e.message; }
}
$('mlRetrainSim').addEventListener('click', () => retrain('simulated'));
$('mlRetrainRecent').addEventListener('click', () => retrain('recent'));

// ======================================================================= data sources
const COLLECTOR_INFO = {
  host: (c) => [`This computer (${c.hostname || ''})`, `${num(c.connections)} connections · ${num(c.processes)} processes · ${num(c.listening)} new listening ports${c.connections_available === false ? ' · no permission to read connections' : ''}`],
  file: (c) => ['Log files', `${(c.paths || []).map(esc).join('<br>')}<br>${num(c.lines_processed)} lines from ${num(c.files_watched)} files`],
  syslog: (c) => ['Syslog', `${esc(c.listen)} · ${num(c.messages_received)} messages`],
  kafka: (c) => ['Kafka', `${(c.topics || []).map(esc).join(', ')} · ${num(c.messages_received)} messages`],
};
async function loadSources() {
  try {
    const s = await api('/api/v1/sources');
    const counts = s.events_by_source_1h || {};
    const cards = (s.collectors || []).map((c) => {
      const [title, detail] = (COLLECTOR_INFO[c.type] || ((x) => [x.type, '']))(c);
      return `<div class="collector"><div class="h"><span class="dot ${c.running ? 'ok' : 'bad'}"></span>${esc(title)}</div>
        <div class="n">${num(counts[c.type] || 0)}</div><div class="hint">${detail}</div></div>`;
    });
    for (const extra of ['api', 'upload', 'simulation']) {
      if (counts[extra]) cards.push(`<div class="collector"><div class="h"><span class="dot ok"></span>${esc(SOURCE_NAMES[extra])}</div><div class="n">${num(counts[extra])}</div><div class="hint">${extra === 'simulation' ? 'generated test traffic' : extra === 'upload' ? 'imported from files in this console' : 'sent to /api/v1/ingest'}</div></div>`);
    }
    $('collectors').innerHTML = cards.join('') || '<div class="hint">No collectors enabled (config/ingestion.yaml).</div>';
    const fileCollector = (s.collectors || []).find((c) => c.type === 'file');
    if (fileCollector && fileCollector.paths && fileCollector.paths[0]) $('rawFolder').textContent = fileCollector.paths[0].replace(/[\\/][^\\/]*$/, '');
    renderSimulation(s.simulation);
  } catch (e) { toast(e.message, true); }
  $('curlSnippet').textContent = `curl -X POST ${location.origin}/api/v1/ingest -H "Content-Type: application/json" ${store.get('soc.apiKey') ? '-H "X-API-Key: <key>" ' : ''}\\\n  -d '{"event_type":"ssh_failed","src_ip":"203.0.113.10","user":"root"}'`;
}
LOADERS.sources = loadSources;

function renderSimulation(sim) {
  if (!sim) return;
  if ($('simScenario').options.length <= 1) sim.scenarios_available.forEach((n) => $('simScenario').add(new Option(cap(n), n)));
  $('simToggle').textContent = sim.running ? 'Stop simulation' : 'Start simulation';
  $('simToggle').className = sim.running ? 'btn danger' : 'btn primary';
  const sc = sim.scorecard;
  $('simScore').innerHTML = [['Attacks injected', sc.attacks_injected], ['Detected', `${sc.attacks_detected} / ${sc.attacks_evaluated}`],
    ['Detection rate', sc.detection_rate === null ? '—' : `${Math.round(sc.detection_rate * 100)}%`],
    ['Mean time to detect', sc.mean_time_to_detect_s === null ? '—' : `${sc.mean_time_to_detect_s} s`],
    ['Alerts on normal traffic', sc.false_positive_alerts], ['Simulated events', num(sim.events_sent)]]
    .map(([l, v]) => `<div class="kpi"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div></div>`).join('');
  $('simTable').innerHTML = (sim.recent || []).length ? sim.recent.map((r) => {
    const missed = !r.detected && Date.now() - new Date(r.started_at) > 60000;
    return `<tr><td>${tm(r.started_at)}</td><td>${esc(cap(r.scenario))}</td><td>${ent(r.entity)}</td>
      <td>${r.detected ? '<span class="badge done">Detected</span>' : missed ? '<span class="badge failed">Missed</span>' : '<span class="badge planned">In progress</span>'}</td>
      <td class="num">${r.time_to_detect_s === null ? '—' : `${r.time_to_detect_s} s`}</td></tr>`;
  }).join('') : '<tr><td colspan="5" class="empty">No simulated attacks yet.</td></tr>';
}
$('simToggle').addEventListener('click', async () => {
  try {
    const running = state.stats && state.stats.simulation.running;
    const sim = running ? await post('/api/v1/simulation/stop')
      : await post('/api/v1/simulation/start', { rate: Number($('simRate').value) || 5, attack_interval: Number($('simInterval').value) || 45 });
    if (state.stats) state.stats.simulation = sim;
    renderSimulation(sim); refresh();
  } catch (e) { toast(e.message, true); }
});
$('simInject').addEventListener('click', async () => {
  try { const r = await post('/api/v1/simulation/inject', { scenario: $('simScenario').value || null }); toast(`Injected ${cap(r.scenario)} from ${r.entity}`); }
  catch (e) { toast(e.message, true); }
});

// log import: read in the browser, send raw lines in batches (keeps the server simple and the file's own timestamps)
$('importBtn').addEventListener('click', async () => {
  const files = [...$('importFile').files];
  if (!files.length) { $('importMsg').textContent = 'Choose one or more log files first.'; return; }
  const bar = $('importProgress'), fill = bar.firstElementChild;
  bar.hidden = false; $('importBtn').disabled = true;
  let sent = 0, alerts = new Set(), total = 0;
  try {
    const all = [];
    for (const f of files) {
      if (f.size > 200 * 1024 * 1024) throw new Error(`${f.name} is larger than 200 MB - put it in the log folder instead`);
      const text = await f.text();
      text.split(/\r?\n/).forEach((line) => { if (line.trim()) all.push({ raw_message: line.trim(), source_type: 'upload', source_path: f.name }); });
    }
    total = all.length;
    for (let i = 0; i < all.length; i += 500) {
      const r = await post('/api/v1/ingest', { events: all.slice(i, i + 500) });
      sent += r.accepted;
      r.alert_ids.forEach((a) => alerts.add(a));
      fill.style.width = `${Math.round(((i + 500) / all.length) * 100)}%`;
      $('importMsg').textContent = `${num(sent)} of ${num(total)} lines analysed…`;
    }
    $('importMsg').innerHTML = `Imported <b>${num(sent)}</b> events from ${files.length} file(s) → <b>${alerts.size}</b> alerts raised or updated. <a data-goto="alerts">View alerts</a>`;
    refresh();
  } catch (e) { $('importMsg').textContent = `Import failed: ${e.message}`; }
  finally { $('importBtn').disabled = false; setTimeout(() => { bar.hidden = true; fill.style.width = '0'; }, 1500); }
});

// ======================================================================= settings
async function loadSettings() {
  $('apiKey').value = store.get('soc.apiKey');
  $('analystName').value = store.get('soc.analyst');
  $('themeSelect').value = store.get('soc.theme', 'auto');
  try {
    const h = await api('/health');
    const s = h.system || {};
    $('systemInfo').innerHTML = kv([
      ['Version', esc(h.version)], ['Health', badge(h.status === 'healthy' ? 'done' : 'failed').replace(/>.*</, `>${esc(cap(h.status))}<`)],
      ['Response mode', esc(cap(h.response_mode))], ['API key required', h.auth_required ? 'Yes' : 'No'],
      ...Object.entries(h.components).map(([k, v]) => [cap(k), esc(cap(v))]),
      ['Uptime', `${Math.floor((s.uptime_seconds || 0) / 60)} min`], ['CPU', s.cpu_percent !== undefined ? `${s.cpu_percent}%` : '—'],
      ['Memory (this process)', s.process_memory_mb ? `${s.process_memory_mb} MB` : '—'],
      ['API documentation', '<a href="/api/docs" target="_blank">/api/docs</a>'], ['Prometheus metrics', '<a href="/metrics" target="_blank">/metrics</a>'],
    ]);
  } catch (e) { $('systemInfo').textContent = e.message; }
}
LOADERS.settings = loadSettings;
$('settingsForm').addEventListener('submit', (e) => {
  e.preventDefault();
  store.set('soc.apiKey', $('apiKey').value.trim());
  store.set('soc.analyst', $('analystName').value.trim());
  store.set('soc.theme', $('themeSelect').value);
  applyTheme($('themeSelect').value);
  $('settingsMsg').textContent = 'Saved.';
  connectWs(true); refresh();
});
$('clearData').addEventListener('click', async () => {
  if (!confirm('Delete all stored events, alerts and responses? Threat intel and blocked IPs are kept.')) return;
  try { await post('/api/v1/admin/clear'); toast('Data cleared'); refresh(); } catch (e) { toast(e.message, true); }
});

// ======================================================================= live updates
let ws = null, wsTimer = null, refreshTimer = null;
function scheduleRefresh() { clearTimeout(refreshTimer); refreshTimer = setTimeout(refresh, 600); }
function connectWs(force = false) {
  if (ws && !force) return;
  if (ws) { ws.onclose = null; ws.close(); }
  const key = store.get('soc.apiKey');
  ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws${key ? `?api_key=${encodeURIComponent(key)}` : ''}`);
  ws.onopen = () => { $('dotWs').className = 'dot ok'; $('txtWs').textContent = 'Live'; };
  ws.onclose = () => { $('dotWs').className = 'dot bad'; $('txtWs').textContent = 'Disconnected'; ws = null; clearTimeout(wsTimer); wsTimer = setTimeout(() => connectWs(), 3000); };
  ws.onmessage = (m) => {
    let msg; try { msg = JSON.parse(m.data); } catch { return; }
    if (msg.type === 'event') addStreamEvent(msg.event);
    else if (msg.type === 'stats') { state.stats = msg.stats; renderChrome(msg.stats); if (state.page === 'overview') renderOverview(msg.stats); }
    else if (msg.type === 'simulation' && state.page === 'sources') renderSimulation(msg.simulation);
    else if (msg.type === 'alert') {
      if (['critical', 'high'].includes(msg.alert.severity)) toast(`${cap(msg.alert.severity)}: ${msg.alert.rule_name}`);
      if (state.page === 'overview') loadRecentAlerts();
      if (state.page === 'alerts') loadAlerts();
      scheduleRefresh();
    } else if (msg.type === 'response' && state.page === 'response') loadResponse();
  };
}
setInterval(() => { $('evRate').textContent = `${num(state.received)} events received`; }, 1000);

// ======================================================================= boot
loadPlaybooks();
refresh();
connectWs();
setInterval(() => { if (!ws || ws.readyState !== 1) refresh(); }, 5000);
