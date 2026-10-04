/* BugHunter Pro local-first dashboard. All displayed scan data comes from SQLite or real SSE events. */
(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const slot = $('#page-slot');
  const state = { page: 'dashboard', events: [], projects: [], scanners: [], summary: null, source: null, unread: 0 };
  const titles = {
    dashboard: 'Dashboard', projects: 'Projects', scope: 'Scope', assets: 'Assets', hosts: 'Hosts & Services',
    endpoints: 'Endpoints', technologies: 'Technologies', scans: 'Live scans', findings: 'Findings', evidence: 'Evidence',
    reports: 'Reports', integrations: 'Integrations', settings: 'Settings', lab: 'Local lab', events: 'Logs & events'
  };

  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const shortDate = (value) => value ? new Date(value).toLocaleString() : '—';
  const api = async (url, options = {}) => {
    const response = await fetch(url, { headers: { 'Accept': 'application/json', ...(options.body ? {'Content-Type':'application/json'} : {}) }, ...options });
    let payload;
    try { payload = await response.json(); } catch { throw new Error(`Unexpected response (${response.status})`); }
    if (!response.ok || payload.success === false) throw new Error(payload.error || `Request failed (${response.status})`);
    return payload.data ?? payload;
  };
  const post = (url, body = {}) => api(url, { method: 'POST', body: JSON.stringify(body) });
  const patch = (url, body = {}) => api(url, { method: 'PATCH', body: JSON.stringify(body) });
  const toast = (message, kind = 'info') => {
    const node = document.createElement('div');
    node.className = `toast toast-${kind}`;
    node.setAttribute('role', 'status');
    node.textContent = message;
    $('#toast-region').append(node);
    window.setTimeout(() => node.remove(), 4200);
  };
  const empty = (title, detail = 'No records have been collected for this project yet.') => `<div class="empty-state"><span class="empty-mark">—</span><strong>${esc(title)}</strong><p>${esc(detail)}</p></div>`;
  const badge = (value, type = '') => `<span class="badge ${esc(type || `badge-${String(value || '').toLowerCase().replace(/[^a-z0-9]+/g,'-')}`)}">${esc(value || '—')}</span>`;
  const panel = (title, subtitle, body, actions = '') => `<section class="panel"><header class="panel-header"><div><h2>${esc(title)}</h2>${subtitle ? `<p>${esc(subtitle)}</p>` : ''}</div>${actions}</header>${body}</section>`;
  const table = (headers, rows, emptyTitle = 'Nothing to show') => rows.length ? `<div class="table-wrap"><table><thead><tr>${headers.map((x) => `<th scope="col">${esc(x)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>` : empty(emptyTitle);
  const cardMetric = (label, value, hint, icon) => `<article class="metric-card"><div class="metric-icon">${icon}</div><div><p>${esc(label)}</p><strong>${esc(value ?? 0)}</strong><small>${esc(hint || 'From active project data')}</small></div></article>`;
  const methodClass = (method) => `method-${String(method || 'GET').toLowerCase()}`;
  const severityClass = (severity) => `severity-${String(severity || 'info').toLowerCase()}`;

  async function loadProjects() {
    state.projects = await api('/api/projects');
    const picker = $('#project-picker');
    picker.innerHTML = state.projects.map((project) => `<option value="${project.id}" ${project.active ? 'selected' : ''}>${esc(project.name)}${project.active ? ' · active' : ''}</option>`).join('');
    const scope = await api('/api/scope');
    state.scopeRules = scope;
    $('#sidebar-scope-count').textContent = `${scope.in_scope.length} in scope`;
  }

  function setPage(page, focus = false) {
    if (!titles[page]) page = 'dashboard';
    state.page = page;
    $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.page === page));
    $('#page-title').textContent = titles[page];
    document.title = `${titles[page]} · BugHunter Pro`;
    $('#sidebar').classList.remove('sidebar-open');
    $('#mobile-menu').setAttribute('aria-expanded', 'false');
    renderPage().catch((error) => {
      slot.innerHTML = `<section class="panel error-panel"><h2>Could not load ${esc(titles[page])}</h2><p>${esc(error.message)}</p></section>`;
    });
    if (focus) $('#main-content').focus({ preventScroll: true });
  }

  function liveEventRows(items, max = 8) {
    if (!items.length) return empty('No live events yet', 'Events appear here when backend scans perform work.');
    return `<ol class="event-list">${items.slice(0, max).map((event) => `<li class="event-row"><time>${esc(shortDate(event.timestamp))}</time><span class="event-type">${esc(event.type)}</span><span class="event-message">${esc(event.message)}</span><span class="event-target">${esc(event.target || '')}</span></li>`).join('')}</ol>`;
  }

  function activeScanRows(items) {
    if (!items.length) return empty('No active scans', 'Queued and running jobs will appear here with backend-derived request counts and events.');
    return `<div class="scan-stack">${items.map((scan) => {
      const progress = Number.isFinite(scan.progress) ? Math.max(0, Math.min(100, scan.progress)) : null;
      const bar = progress === null ? '<div class="progress-track"><div class="progress-indeterminate"></div></div>' : `<div class="progress-track"><div class="progress-fill" style="width:${progress}%"></div></div>`;
      return `<article class="active-scan"><div class="scan-topline"><strong>${esc(scan.display_id || `SCAN-${scan.id}`)}</strong>${badge(scan.status)}<span>${esc(scan.module)}</span><span class="scan-target">${esc(scan.target)}</span></div><div class="scan-progress-row">${bar}<span>${progress === null ? 'Live' : `${progress}%`}</span></div><div class="scan-meta"><span>${esc(scan.current_action || 'Waiting for worker')}</span><span>${esc(scan.requests || 0)} requests · ${esc(scan.rate || 0)} req/s</span><span>Started ${esc(shortDate(scan.started_at))}</span></div><div class="scan-actions">${scan.status === 'PAUSED' ? `<button class="button button-small" data-action="resume" data-scan="${scan.id}">Resume</button>` : `<button class="button button-small" data-action="pause" data-scan="${scan.id}" ${['QUEUED','STARTING','RUNNING'].includes(scan.status) ? '' : 'disabled'}>Pause</button>`}<button class="button button-small button-danger" data-action="cancel" data-scan="${scan.id}">Cancel</button></div></article>`;
    }).join('')}</div>`;
  }

  function chartBars(title, items, color = '') {
    const rows = Object.entries(items || {}).filter(([, value]) => Number(value) > 0);
    const max = Math.max(1, ...rows.map(([, value]) => Number(value)));
    const body = rows.length ? `<div class="bar-chart">${rows.map(([name, value]) => `<div class="bar-row"><span>${esc(name.replaceAll('_',' '))}</span><div class="bar-track"><span class="bar ${color}" style="width:${Math.max(2, Number(value) / max * 100)}%"></span></div><b>${esc(value)}</b></div>`).join('')}</div>` : empty('No measurements yet', 'Bars are calculated from records in the active project.');
    return panel(title, 'Database-backed counts; no estimated score.', body);
  }

  async function renderDashboard() {
    const [summary, scans, events, scanners] = await Promise.all([
      api('/api/summary'), api('/api/scans?limit=10'), api('/api/events?limit=10'), api('/api/scanners')
    ]);
    state.summary = summary;
    state.scanners = scanners;
    const active = scans.filter((scan) => ['QUEUED','STARTING','RUNNING','PAUSED','CANCELLING'].includes(scan.status));
    const opts = scanners.map((scan) => `<option value="${esc(scan.key)}">${esc(scan.name)}</option>`).join('');
    slot.innerHTML = `
      <section class="welcome-row"><div><p class="eyebrow">ASSESSMENT OVERVIEW</p><h1>${esc(summary.project?.name || 'Active project')}</h1><p class="muted">Observable inventory and review workflow for explicitly authorized assets.</p></div><div class="scope-chip"><span class="safe-dot"></span><span><b>SAFE MODE ON</b><small>${esc(summary.scope_count || 0)} scope rules · ${esc(summary.exclusion_count || 0)} exclusions</small></span></div></section>
      <section class="metric-grid">${cardMetric('Assets', summary.assets, 'Hosts recorded', '◇')}${cardMetric('Endpoints', summary.endpoints, 'Methods and URLs recorded', '↗')}${cardMetric('Potential findings', summary.needs_review, 'Manual review required', '△')}${cardMetric('Active scans', summary.active_scans, 'Persisted queue state', '▤')}</section>
      ${panel('Start an authorized scan', 'Every target is checked against this project’s Scope Guard before it is queued.', `<form id="scan-create-form" class="scan-create-form"><label>Target URL or host<input name="target" required maxlength="2000" placeholder="https://in-scope.example" autocomplete="url"></label><label>Module<select name="module"><option value="baseline">Baseline · original five scanners</option>${opts}</select></label><button class="button button-primary" type="submit">Queue scan</button></form><p class="form-note">Baseline runs the preserved headers, TLS, DNS/origin, CORS, and configured port checks. It may take time under the shared rate limiter.</p>`)}
      <section class="dashboard-two-col">${panel('Active scans', 'Live state from the persistent scan queue.', activeScanRows(active))}${panel('Live events', 'Server-sent events from actual worker activity.', liveEventRows(events, 7))}</section>
      <section class="dashboard-two-col">${chartBars('Finding severity', summary.severity || {}, 'bar-severity')}${chartBars('Finding status', summary.finding_status || {}, '')}</section>
      ${panel('Coverage indicators', 'Counts only; this is not a security score.', `<div class="coverage-grid"><div><span>Confirmed</span><b>${esc(summary.confirmed_findings || 0)}</b></div><div><span>Technologies</span><b>${esc(summary.technologies || 0)}</b></div><div><span>Services</span><b>${esc(summary.services || 0)}</b></div><div><span>Evidence records</span><b>${esc(summary.evidence || 0)}</b></div></div>`)}
    `;
  }

  async function renderProjects() {
    const projects = await api('/api/projects');
    const rows = projects.map((item) => `<tr><td><strong>${esc(item.name)}</strong>${item.active ? ` ${badge('ACTIVE','badge-running')}` : ''}</td><td>${esc(item.program || '—')}</td><td>${esc(item.description || '—')}</td><td>${esc(shortDate(item.created_at))}</td><td>${item.active ? 'Current' : `<button class="button button-small" data-action="activate-project" data-project="${item.id}">Open project</button>`}</td></tr>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">RESEARCH WORKSPACES</p><h1>Projects</h1><p class="muted">Each project owns its scope rules, scans, assets, evidence and findings.</p></section>${panel('Create project', 'A new project begins with an empty scope.', `<form id="project-create-form" class="inline-form"><label>Project name<input name="name" required maxlength="100" placeholder="Authorized assessment"></label><label>Program / client<input name="program" maxlength="200" placeholder="Optional"></label><label>Description<input name="description" maxlength="1000" placeholder="Purpose and authorization notes"></label><button class="button button-primary">Create</button></form>`)}${panel('Project list', 'Local SQLite project records.', table(['Project','Program','Description','Created','Action'], rows, 'No projects yet'))}`;
  }

  async function renderScope() {
    const [scope, rules] = await Promise.all([api('/api/scope'), api('/api/scope/rules')]);
    const rows = rules.map((rule) => `<tr><td>${badge(rule.kind, rule.kind === 'exclude' ? 'badge-danger' : 'badge-running')}</td><td><code>${esc(rule.rule)}</code></td><td>${esc(shortDate(rule.created_at))}</td><td><button class="button button-small button-quiet" data-action="delete-scope" data-kind="${esc(rule.kind)}" data-rule="${esc(rule.rule)}">Remove</button></td></tr>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">MANDATORY AUTHORIZATION CONTROL</p><h1>Scope Guard</h1><p class="muted">Network actions are refused unless their host matches an included rule and no exclusion applies.</p></section><div class="notice notice-warning"><strong>Scope is not a target list suggestion; it is enforced on every request and redirect.</strong><span>Private and loopback systems require an explicit IP/CIDR rule. Discovered names are not automatically scanned.</span></div>${panel('Add scope rule', 'Exact domains, wildcard domains, IPv4/IPv6 and CIDR are supported.', `<form id="scope-form" class="inline-form"><label>Rule<input name="rule" required maxlength="255" placeholder="example.com, *.example.com, 127.0.0.1/32"></label><label>Rule type<select name="kind"><option value="include">Include</option><option value="exclude">Exclude</option></select></label><button class="button button-primary">Add rule</button></form>`)}${panel('Current scope', `${scope.in_scope.length} included · ${scope.exclusions.length} exclusions; exclusions always take precedence.`, table(['Type','Rule','Added','Action'], rows, 'No scope rules. Scans remain blocked until explicit scope is added.'))}`;
  }

  async function renderAssets() {
    const data = await api('/api/assets/graph');
    const rows = data.assets.map((item) => {
      const ips = Array.isArray(item.details?.addresses) ? item.details.addresses.join(', ') : '—';
      const scheme = item.details?.scheme || '—';
      return `<tr><td><strong>${esc(item.host)}</strong></td><td>${esc(ips)}</td><td>${esc(scheme)}</td><td>${badge(item.status || 'observed')}</td><td>${esc(shortDate(item.last_seen))}</td><td>${item.in_scope ? badge('in scope','badge-running') : badge('scope rule needed','badge-muted')}</td></tr>`;
    });
    const links = data.relations.map((edge) => `<li><code>${esc(edge.source_value)}</code> <span>${esc(edge.relation.replaceAll('_',' '))}</span> <code>${esc(edge.target_value)}</code></li>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">ASSET GRAPH</p><h1>Assets</h1><p class="muted">Nodes and relationships discovered by real scoped scanner execution.</p></section>${panel('Discovered hosts', `${data.assets.length} host records`, table(['Hostname','IP addresses','Protocol','Status','Last seen','Scope'], rows, 'No hosts recorded yet'))}${panel('Relationships', 'Host-to-IP, host-to-endpoint and host-to-technology links.', links.length ? `<ul class="relationship-list">${links.slice(0,500).join('')}</ul>` : empty('No relationships yet'))}`;
  }

  async function renderHosts() {
    const [assets, services] = await Promise.all([api('/api/hosts'), api('/api/services')]);
    const hostRows = assets.map((item) => `<tr><td>${esc(item.host)}</td><td>${esc((item.details?.addresses || []).join(', ') || '—')}</td><td>${badge(item.status || 'observed')}</td><td>${esc(shortDate(item.last_seen))}</td></tr>`);
    const serviceRows = services.map((item) => `<tr><td>${esc(item.host)}</td><td>${esc(item.ip || '—')}</td><td>${esc(item.port)}/${esc(item.protocol)}</td><td>${esc(item.service)}</td><td>${esc(item.version || '—')}</td><td>${badge(item.state)}</td><td>${esc(shortDate(item.last_seen))}</td></tr>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">NETWORK INVENTORY</p><h1>Hosts &amp; services</h1><p class="muted">Open-service records are created only by explicit configured port checks or the read-only exposure module.</p></section>${panel('Hosts', 'Scope-validated host inventory.', table(['Host','IP addresses','Status','Last seen'], hostRows, 'No hosts recorded yet'))}${panel('Services', 'No login, query, authentication or data extraction is performed.', table(['Host','IP','Port','Service','Version','State','Last seen'], serviceRows, 'No services recorded yet'))}`;
  }

  async function renderEndpoints() {
    const endpoints = await api('/api/endpoints');
    const filter = state.endpointFilter || 'ALL';
    const filtered = filter === 'ALL' ? endpoints : endpoints.filter((item) => item.method === filter);
    const rows = filtered.map((item) => `<tr><td>${badge(item.method, `method ${methodClass(item.method)}`)}</td><td><code class="url-cell">${esc(item.url)}</code></td><td>${esc(item.status_code ?? '—')}</td><td>${esc(item.content_type || '—')}</td><td>${esc((item.details?.parameters || item.details?.query_parameters || []).join?.(', ') || '—')}</td><td>${esc(item.details?.auth || 'Unknown')}</td><td>${esc(item.details?.technology || '—')}</td><td>${esc(shortDate(item.last_seen))}</td></tr>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">APPLICATION SURFACE</p><h1>Endpoints</h1><p class="muted">Endpoint records come from probes, HTML, robots/sitemap, docs and bounded crawler results. Forms are inventoried, not submitted.</p></section>${panel('Endpoint inventory', `${filtered.length} of ${endpoints.length} endpoints`, `<div class="filter-row"><label for="endpoint-filter">Method filter</label><select id="endpoint-filter"><option ${filter==='ALL'?'selected':''}>ALL</option>${['GET','HEAD','OPTIONS','POST','PUT','DELETE','PATCH'].map((m)=>`<option ${filter===m?'selected':''}>${m}</option>`).join('')}</select></div>${table(['Method','URL','Status','Content type','Parameters','Auth','Technology','Last seen'], rows, 'No endpoints recorded yet')}`)}`;
  }

  async function renderTechnologies() {
    const items = await api('/api/technologies');
    const rows = items.map((item) => `<tr><td><strong>${esc(item.technology)}</strong></td><td>${esc(item.category)}</td><td>${badge(item.confidence, item.confidence === 'HIGH' ? 'badge-running' : 'badge-muted')}</td><td>${esc(item.host)}</td><td>${esc(item.source || '—')}</td><td>${esc(item.evidence || '—')}</td><td>${esc(shortDate(item.last_seen))}</td></tr>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">EVIDENCE-BASED FINGERPRINTS</p><h1>Technologies</h1><p class="muted">Indicators include their source and confidence; a fingerprint is not proof of a specific version or vulnerability.</p></section>${panel('Technology inventory', `${items.length} observations`, table(['Technology','Category','Confidence','Host','Source','Evidence','Last seen'], rows, 'No technology indicators recorded yet'))}`;
  }

  async function renderScans() {
    const scans = await api('/api/scans?limit=200');
    const active = scans.filter((scan) => ['QUEUED','STARTING','RUNNING','PAUSED','CANCELLING'].includes(scan.status));
    const history = scans.map((scan) => `<tr><td><strong>${esc(scan.display_id)}</strong></td><td>${esc(scan.target)}</td><td>${esc(scan.module)}</td><td>${badge(scan.status)}</td><td>${Number.isFinite(scan.progress) ? `${scan.progress}%` : scan.status === 'RUNNING' ? 'indeterminate' : '—'}</td><td>${esc(scan.requests || 0)}</td><td>${esc(scan.rate || 0)} req/s</td><td>${esc(scan.current_action || '—')}</td><td>${esc(shortDate(scan.started_at))}</td><td>${['FAILED','CANCELLED'].includes(scan.status) ? `<button class="button button-small" data-action="retry" data-scan="${scan.id}">Retry</button>` : ''}</td></tr>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">PERSISTENT JOB QUEUE · SSE</p><h1>Live scans</h1><p class="muted">Pause and cancellation take effect at cooperative safe checkpoints. Progress is only shown when the backend has a measurable unit of work.</p></section>${panel('Active jobs', 'Request counts, rates and current actions are updated by worker events.', activeScanRows(active))}${panel('Scan history', 'Unfinished jobs are marked FAILED after restart, never silently completed.', table(['ID','Target','Module','State','Progress','Requests','Rate','Current action','Started','Action'], history, 'No scans have been queued yet'))}`;
  }

  async function renderFindings() {
    const params = new URLSearchParams();
    for (const key of ['severity','confidence','status','module','target']) if (state.findingFilters?.[key]) params.set(key, state.findingFilters[key]);
    const items = await api(`/api/findings?${params}`);
    const rows = items.map((item) => {
      const details = `<details class="finding-detail"><summary>Review evidence and notes</summary><dl><dt>Description</dt><dd>${esc(item.description || '—')}</dd><dt>Impact</dt><dd>${esc(item.impact || '—')}</dd><dt>Evidence</dt><dd>${esc(item.evidence || '—')}</dd><dt>Observed behavior</dt><dd>${esc(item.observed_behavior || '—')}</dd><dt>Reproduction notes</dt><dd>${esc(item.reproduction_notes || '—')}</dd><dt>Remediation</dt><dd>${esc(item.remediation || '—')}</dd></dl><form data-finding-notes="${esc(item.finding_id)}"><label>Researcher notes<textarea name="researcher_notes" rows="3" maxlength="4000">${esc(item.researcher_notes || '')}</textarea></label><button class="button button-small">Save notes</button></form></details>`;
      return `<tr><td><code>${esc(item.finding_id)}</code></td><td>${badge(item.severity, severityClass(item.severity))}</td><td>${badge(item.confidence)}</td><td><strong>${esc(item.title)}</strong><small class="cell-subtitle">${esc(item.category)} · ${esc(item.module || 'scanner')}</small></td><td>${esc(item.target)}</td><td>${esc(item.endpoint || '—')}</td><td>${esc(shortDate(item.created_at))}</td><td>${esc(shortDate(item.updated_at))}</td><td><select data-finding-status="${esc(item.finding_id)}" aria-label="Status for ${esc(item.finding_id)}">${['NEW','NEEDS_REVIEW','CONFIRMED','FALSE_POSITIVE','REPORTED','RESOLVED'].map((status)=>`<option ${item.status===status?'selected':''}>${status}</option>`).join('')}</select></td><td>${details}</td></tr>`;
    });
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">HUMAN REVIEW REQUIRED</p><h1>Findings</h1><p class="muted">Automated findings enter NEEDS_REVIEW. Confirming requires a deliberate researcher action and typed verification.</p></section>${panel('Finding filters', 'Filter the active project’s persisted findings.', `<form id="finding-filter-form" class="filter-grid">${[['severity','Severity',['','INFO','LOW','MEDIUM','HIGH','CRITICAL']],['confidence','Confidence',['','LOW','MEDIUM','HIGH']],['status','Status',['','NEW','NEEDS_REVIEW','CONFIRMED','FALSE_POSITIVE','REPORTED','RESOLVED']]].map(([name,label,values])=>`<label>${label}<select name="${name}">${values.map((v)=>`<option value="${v}" ${(state.findingFilters?.[name]||'')===v?'selected':''}>${v||'All'}</option>`).join('')}</select></label>`).join('')}<label>Target contains<input name="target" value="${esc(state.findingFilters?.target || '')}" maxlength="150"></label><label>Module contains<input name="module" value="${esc(state.findingFilters?.module || '')}" maxlength="100"></label><button class="button">Apply filters</button></form>`)}${panel('Finding queue', `${items.length} matching logical findings; correlated endpoints are shown in the finding detail.`, table(['ID','Severity','Confidence','Finding','Target','Endpoint','First seen','Last seen','Status','Review / notes'], rows, 'No findings match this filter'))}`;
  }

  async function renderEvidence() {
    const items = await api('/api/evidence?limit=1000');
    const rows = items.map((item) => `<tr><td>${esc(shortDate(item.timestamp))}</td><td>${esc(item.finding_id || '—')}</td><td>${esc(item.request_method || '—')}</td><td>${esc(item.target)}</td><td>${esc(item.endpoint || '—')}</td><td>${esc(item.status_code ?? '—')}</td><td>${esc(item.response_size ?? '—')}</td><td><details><summary>Inspect sanitized evidence</summary><p>${esc(item.evidence_description || '—')}</p><pre>${esc(item.response_excerpt || JSON.stringify(item.sanitized_request || {}, null, 2))}</pre></details></td></tr>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">SANITIZED OBSERVATIONS</p><h1>Evidence</h1><p class="muted">Bodies, cookies and credential material are minimized or redacted before persistence.</p></section>${panel('Evidence records', `${items.length} records`, table(['Timestamp','Finding','Method','Target','Endpoint','Status','Size','Evidence'], rows, 'No evidence has been stored yet'))}`;
  }

  async function renderReports() {
    const items = await api('/api/reports');
    const rows = items.map((item) => `<tr><td>${esc(item.title)}</td><td>${badge(item.format.toUpperCase())}</td><td>${badge(item.status)}</td><td>${esc(shortDate(item.created_at))}</td><td><a class="button button-small" href="/api/reports/${item.id}/download">Download</a></td></tr>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">REDACTED EXPORTS</p><h1>Reports</h1><p class="muted">Reports distinguish automated signals from human-verified findings. No report is submitted automatically.</p></section>${panel('Generate report', 'Choose a format from the active project records.', `<form id="report-form" class="inline-form"><label>Format<select name="format"><option>html</option><option>json</option><option>pdf</option></select></label><button class="button button-primary">Generate report</button></form><p class="form-note">PDF generation requires the optional ReportLab package.</p>`)}${panel('Report history', 'Only reports recorded for the active project are shown.', table(['Title','Format','Status','Created','File'], rows, 'No reports generated yet'))}`;
  }

  async function renderIntegrations() {
    const catalog = await api('/api/integrations');
    const items = catalog.tools || [];
    const provider = (catalog.providers || [])[0] || {enabled:false,name:'NVD'};
    const cards = items.map((item) => `<article class="integration-card"><div class="integration-head"><div><h3>${esc(item.name)}</h3><code>${esc(item.binary)}</code></div>${badge(item.installed ? 'INSTALLED' : 'NOT INSTALLED', item.installed ? 'badge-running' : 'badge-muted')}</div><p>${esc(item.description)}</p><div class="integration-meta"><span>Policy</span><b>${esc(item.policy.replaceAll('_',' '))}</b></div><div class="integration-meta"><span>Version</span><b>${esc(item.version || '—')}</b></div><div class="integration-meta"><span>Enabled</span><b>${item.enabled ? 'Yes' : 'No'}</b></div>${['nmap','subfinder','amass'].includes(item.key)?`<button class="button button-small" data-action="toggle-integration" data-tool="${esc(item.key)}" data-enabled="${item.enabled?'true':'false'}">${item.enabled?'Disable':'Enable'} adapter</button>`:''}</article>`);
    const advisories = state.intelResult?.advisories || [];
    const intelOutput = state.intelResult ? `<div class="notice notice-warning"><strong>Keyword candidates only · confidence LOW · manual verification required.</strong><span>${esc(state.intelResult.warning || 'A version match has not been validated.')}</span></div>${table(['CVE','CVSS','Severity','Published','Summary','Review'], advisories.map((item)=>`<tr><td>${esc(item.cve)}</td><td>${esc(item.cvss ?? '—')}</td><td>${esc(item.severity)}</td><td>${esc(item.published)}</td><td>${esc(item.summary)}</td><td>${(item.references||[]).map((url)=>`<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">Reference</a>`).join(' · ')}</td></tr>`), 'No candidate advisories returned')}` : '';
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">OPTIONAL TOOL ADAPTERS</p><h1>Integrations</h1><p class="muted">Missing binaries do not disable native scanners. External network tools are not automatically run by dashboard scans.</p></section><div class="integration-grid">${cards.join('')}</div>${panel('Threat intelligence', 'Optional NVD keyword enrichment is cached locally and uses the scoped passive-source allowlist.', `<form id="intel-toggle-form" class="inline-form"><label class="check-label"><input type="checkbox" name="enabled" ${provider.enabled?'checked':''}> Enable opt-in NVD refresh</label><button class="button">Save provider setting</button></form><form id="intel-refresh-form" class="inline-form"><label>Technology<input name="product" required maxlength="100" placeholder="Apache HTTP Server"></label><label>Detected version<input name="version" required maxlength="60" placeholder="2.4.58"></label><button class="button button-primary" ${provider.enabled?'':'disabled'}>Refresh advisory candidates</button></form><p class="form-note">A technology/version keyword result is not a vulnerability determination. The platform does not claim affected-version equivalence and will not submit a report.</p>${intelOutput}`)}${panel('Scope and execution policy', 'Optional command-line integrations remain isolated behind adapters.', '<p class="panel-body">Subprocess adapters use argument arrays, bounded output and timeouts; shell interpolation is not used. Nmap and passive subdomain adapters require explicit enablement and researcher authorization. Nuclei template execution stays disabled in Safe Mode.</p>')}`;
  }

  async function renderSettings() {
    const settings = await api('/api/settings');
    const numberField = (key, label, min, max, step = 1) => `<label>${label}<input type="number" name="${key}" value="${esc(settings[key])}" min="${min}" max="${max}" step="${step}"></label>`;
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">LOCAL POLICY</p><h1>Settings</h1><p class="muted">Safe Mode is always on in the dashboard. Numeric controls have server-side upper bounds.</p></section>${panel('Request and scan limits', 'Limits update in the shared local context; worker-pool changes require an idle queue. Settings are saved to config.json.', `<form id="settings-form" class="settings-grid">${numberField('timeout','Request timeout (seconds)',1,30,0.5)}${numberField('request_interval','Minimum request interval (seconds)',0.25,60,0.25)}${numberField('max_requests','Maximum requests per scan',1,10000)}${numberField('max_response_bytes','Maximum response bytes',4096,5242880)}${numberField('max_crawl_depth','Maximum crawler depth',0,5)}${numberField('max_urls','Maximum crawler URLs',1,500)}${numberField('scan_workers','Concurrent workers',1,5)}<div class="setting-mode"><span>SAFE MODE</span><strong><span class="safe-dot"></span> ENABLED · locked in dashboard</strong></div><button class="button button-primary">Save settings</button></form>`)}${panel('User agent', 'Requests identify this local assessment toolkit.', `<code>${esc(settings.user_agent)}</code>`)}`;
  }

  async function renderLab() {
    const lab = await api('/api/lab/status');
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">LOCAL-ONLY TRAINING FIXTURE</p><h1>Local lab</h1><p class="muted">No public target is required for development or scanner testing.</p></section><div class="notice notice-info"><strong>Loopback binding: ${esc(lab.bind_address)}</strong><span>${esc(lab.note)}</span></div>${panel('Start the lab', 'Run from the repository root in a separate terminal.', `<pre class="command-block">${esc(lab.start_command)}\n# open ${esc(lab.url)}</pre><p>Add <code>127.0.0.1/32</code> to project scope before any scan. The fixture includes intentionally weak headers/CORS and synthetic, harmless application signals. It stores no uploads or real user data.</p><div class="lab-checklist"><span>✓ Loopback-only bind</span><span>✓ No production database</span><span>✓ No command execution</span><span>✓ Synthetic test records only</span></div>`)}${panel('Reset', 'The fixture reset endpoint clears only its in-memory lab counters.', `<code>POST ${esc(lab.url)}${esc(lab.reset_path)}</code><p class="form-note">Reset is a local lab action and is not initiated automatically by the dashboard.</p>`)}`;
  }

  async function renderEvents() {
    const events = await api('/api/events?limit=300');
    state.events = events.slice(-300).reverse();
    const rows = state.events.map((event) => `<tr><td>${esc(shortDate(event.timestamp))}</td><td>${badge(event.type)}</td><td>${badge(event.severity, severityClass(event.severity))}</td><td>${esc(event.message)}</td><td>${esc(event.target || '—')}</td><td>${event.scan_id ? `<a href="#" data-action="open-scan" data-scan="${event.scan_id}">SCAN-${String(event.scan_id).padStart(4,'0')}</a>` : '—'}</td></tr>`);
    slot.innerHTML = `<section class="page-intro"><p class="eyebrow">PERSISTED WORKER EVENTS</p><h1>Logs &amp; events</h1><p class="muted">Events originate from scanner workers, scope enforcement, persistence and operator controls.</p></section>${panel('Activity log', `${events.length} most recent events from SQLite`, table(['Timestamp','Type','Severity','Message','Target','Scan'], rows, 'No events recorded yet'))}`;
  }

  async function renderPage() {
    slot.innerHTML = '<div class="loading-panel">Loading project records…</div>';
    if (state.page === 'dashboard') return renderDashboard();
    if (state.page === 'projects') return renderProjects();
    if (state.page === 'scope') return renderScope();
    if (state.page === 'assets') return renderAssets();
    if (state.page === 'hosts') return renderHosts();
    if (state.page === 'endpoints') return renderEndpoints();
    if (state.page === 'technologies') return renderTechnologies();
    if (state.page === 'scans') return renderScans();
    if (state.page === 'findings') return renderFindings();
    if (state.page === 'evidence') return renderEvidence();
    if (state.page === 'reports') return renderReports();
    if (state.page === 'integrations') return renderIntegrations();
    if (state.page === 'settings') return renderSettings();
    if (state.page === 'lab') return renderLab();
    if (state.page === 'events') return renderEvents();
  }

  function connectEvents() {
    if (!('EventSource' in window)) {
      $('#stream-label').textContent = 'Live events unavailable';
      $('#stream-pill').classList.add('stream-offline');
      return;
    }
    state.source = new EventSource('/api/events/stream');
    state.source.onopen = () => {
      $('#stream-label').textContent = 'Live event stream';
      $('#stream-pill').classList.remove('stream-offline');
    };
    state.source.onerror = () => {
      $('#stream-label').textContent = 'Reconnecting…';
      $('#stream-pill').classList.add('stream-offline');
    };
    const types = ['scan_queued','scan_started','scan_progress','scan_paused','scan_resumed','scan_cancelled','scan_completed','asset_discovered','host_up','endpoint_discovered','technology_detected','finding_created','finding_updated','warning','error','scope_block','rate_limit','task_retry','scope_updated','project_created','report_created'];
    for (const type of types) {
      state.source.addEventListener(type, (message) => {
        let event;
        try { event = JSON.parse(message.data); } catch { return; }
        state.events.unshift(event);
        state.events = state.events.slice(0, 300);
        if (['finding_created','asset_discovered','scan_completed','scope_block','error'].includes(type)) {
          state.unread += 1;
          $('#notification-dot').hidden = false;
        }
        if (['finding_created','scope_block','error','scan_completed'].includes(type)) toast(event.message || type, type === 'error' || type === 'scope_block' ? 'warning' : 'info');
        const shouldRefresh = state.page === 'dashboard' || state.page === 'scans' || state.page === 'events' || (type === 'asset_discovered' && ['assets','hosts'].includes(state.page)) || (type === 'endpoint_discovered' && state.page === 'endpoints') || (type.startsWith('finding_') && state.page === 'findings') || (type === 'technology_detected' && state.page === 'technologies');
        if (shouldRefresh) renderPage().catch(() => {});
      });
    }
  }

  function openSearch() {
    $('#search-overlay').hidden = false;
    $('#global-search').value = '';
    $('#search-results').innerHTML = '<p class="muted pad">Search the active project.</p>';
    $('#global-search').focus();
  }
  function closeSearch() { $('#search-overlay').hidden = true; $('#search-trigger').focus(); }
  let searchTimer;
  $('#global-search').addEventListener('input', () => {
    window.clearTimeout(searchTimer);
    const term = $('#global-search').value.trim();
    if (term.length < 2) { $('#search-results').innerHTML = '<p class="muted pad">Type at least two characters.</p>'; return; }
    searchTimer = window.setTimeout(async () => {
      try {
        const results = await api(`/api/search?q=${encodeURIComponent(term)}`);
        $('#search-results').innerHTML = results.length ? results.map((item) => `<button class="search-result" data-action="search-result" data-kind="${esc(item.kind)}"><span>${badge(item.kind)}</span><strong>${esc(item.value)}</strong><small>${esc(item.detail)}</small></button>`).join('') : '<p class="muted pad">No matching project records.</p>';
      } catch (error) { $('#search-results').innerHTML = `<p class="error-text pad">${esc(error.message)}</p>`; }
    }, 180);
  });

  document.addEventListener('click', async (event) => {
    const nav = event.target.closest('[data-page]');
    if (nav) { setPage(nav.dataset.page, true); return; }
    if (event.target.closest('#search-trigger')) { openSearch(); return; }
    if (event.target.closest('#close-search')) { closeSearch(); return; }
    if (event.target.closest('#event-button')) { state.unread = 0; $('#notification-dot').hidden = true; setPage('events', true); return; }
    if (event.target.closest('#mobile-menu')) {
      const open = $('#sidebar').classList.toggle('sidebar-open');
      $('#mobile-menu').setAttribute('aria-expanded', String(open)); return;
    }
    if (event.target.id === 'search-overlay') { closeSearch(); return; }
    const action = event.target.closest('[data-action]');
    if (!action) return;
    const id = action.dataset.scan;
    try {
      switch (action.dataset.action) {
        case 'pause': await post(`/api/scans/${id}/pause`); toast('Pause requested at next safe checkpoint'); break;
        case 'resume': await post(`/api/scans/${id}/resume`); toast('Scan resumed'); break;
        case 'cancel': if (window.confirm('Cancel this scan at the next safe checkpoint?')) { await post(`/api/scans/${id}/cancel`); toast('Cancellation requested'); } break;
        case 'retry': await post(`/api/scans/${id}/retry`); toast('Retry queued'); break;
        case 'activate-project': await post(`/api/projects/${action.dataset.project}/activate`); await loadProjects(); toast('Active project changed'); setPage('dashboard'); break;
        case 'toggle-integration': {
          const enable = action.dataset.enabled !== 'true';
          if (enable && !window.confirm(`Enable the optional ${action.dataset.tool} adapter? This does not authorize a target or automatically run it.`)) break;
          await patch('/api/settings', {enabled_integrations:{[action.dataset.tool]:enable}});
          toast(`${action.dataset.tool} adapter ${enable?'enabled':'disabled'}; execution still requires explicit researcher action`);
          setPage('integrations');
          break;
        }
        case 'delete-scope': if (window.confirm(`Remove scope rule ${action.dataset.rule}?`)) { await api('/api/scope/rules', {method:'DELETE',body:JSON.stringify({kind:action.dataset.kind,rule:action.dataset.rule})}); await loadProjects(); setPage('scope'); toast('Scope rule removed'); } break;
        case 'open-scan': setPage('scans'); break;
        case 'search-result': closeSearch(); setPage(({asset:'assets',endpoint:'endpoints',finding:'findings',technology:'technologies'})[action.dataset.kind] || 'dashboard'); break;
        case 'reload': window.location.reload(); break;
      }
    } catch (error) { toast(error.message, 'warning'); }
  });

  document.addEventListener('change', async (event) => {
    if (event.target.id === 'project-picker') {
      try { await post(`/api/projects/${event.target.value}/activate`); await loadProjects(); setPage('dashboard'); }
      catch (error) { toast(error.message, 'warning'); await loadProjects(); }
    }
    if (event.target.id === 'endpoint-filter') { state.endpointFilter = event.target.value; renderEndpoints(); }
    if (event.target.matches('[data-finding-status]')) {
      const id = event.target.dataset.findingStatus;
      let confirmation;
      if (event.target.value === 'CONFIRMED') confirmation = window.prompt('After manual verification, type HUMAN VERIFIED to confirm this finding:');
      if (event.target.value === 'CONFIRMED' && confirmation !== 'HUMAN VERIFIED') { toast('Confirmation not changed', 'warning'); renderFindings(); return; }
      try { await patch(`/api/findings/${encodeURIComponent(id)}`, {status:event.target.value, ...(confirmation ? {confirmation} : {})}); toast('Finding status updated'); }
      catch (error) { toast(error.message, 'warning'); renderFindings(); }
    }
  });

  document.addEventListener('submit', async (event) => {
    const form = event.target;
    event.preventDefault();
    try {
      if (form.id === 'scan-create-form') {
        const data = Object.fromEntries(new FormData(form));
        const scan = await post('/api/scans', data);
        toast(`${scan.display_id || 'Scan'} queued`);
        setPage('scans');
      } else if (form.id === 'project-create-form') {
        const data = Object.fromEntries(new FormData(form));
        const project = await post('/api/projects', data);
        await post(`/api/projects/${project.id}/activate`);
        await loadProjects(); toast('Project created and activated'); setPage('dashboard');
      } else if (form.id === 'scope-form') {
        const data = Object.fromEntries(new FormData(form));
        await post('/api/scope/rules', data); await loadProjects(); toast('Scope updated'); setPage('scope');
      } else if (form.id === 'finding-filter-form') {
        state.findingFilters = Object.fromEntries(new FormData(form)); renderFindings();
      } else if (form.dataset.findingNotes) {
        const data = Object.fromEntries(new FormData(form));
        await patch(`/api/findings/${encodeURIComponent(form.dataset.findingNotes)}`, {researcher_notes:data.researcher_notes || ''});
        toast('Researcher notes saved'); renderFindings();
      } else if (form.id === 'report-form') {
        const data = Object.fromEntries(new FormData(form));
        const report = await post('/api/reports', data); toast(`Report ${report.id} generated`); setPage('reports');
      } else if (form.id === 'settings-form') {
        const data = Object.fromEntries(new FormData(form));
        await patch('/api/settings', data); toast('Settings saved'); setPage('settings');
      } else if (form.id === 'intel-toggle-form') {
        const enabled = new FormData(form).has('enabled');
        await patch('/api/settings', {threat_intelligence_enabled:enabled});
        toast(enabled ? 'NVD enrichment enabled; refresh remains manual' : 'NVD enrichment disabled');
        setPage('integrations');
      } else if (form.id === 'intel-refresh-form') {
        const data = Object.fromEntries(new FormData(form));
        state.intelResult = await post('/api/threat-intelligence/refresh', data);
        toast('Advisory candidates refreshed; manual review required');
        renderIntegrations();
      }
    } catch (error) { toast(error.message, 'warning'); }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !$('#search-overlay').hidden) closeSearch();
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); openSearch(); }
    if (event.key === '?' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)) { event.preventDefault(); openSearch(); }
  });

  async function init() {
    try {
      await loadProjects();
      const scope = await api('/api/scope');
      state.scopeRules = scope;
      if (!scope.safe_mode) toast('Unexpected policy state: Safe Mode should be enabled', 'warning');
      connectEvents();
      await renderDashboard();
    } catch (error) {
      slot.innerHTML = `<section class="panel error-panel"><h2>Workspace unavailable</h2><p>${esc(error.message)}</p><button class="button" data-action="reload">Retry</button></section>`;
    }
  }
  init();
})();
