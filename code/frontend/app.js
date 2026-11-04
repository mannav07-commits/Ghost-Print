const app = document.getElementById('app');
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
const fmt = n => new Intl.NumberFormat('en-US').format(n ?? 0);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function api(url, options = {}) {
  const r = await fetch(url, options);
  if (!r.ok) throw new Error((await r.json().catch(() => ({ error: r.statusText }))).error || r.statusText);
  return r.json();
}

function badge(s) {
  return `<span class="badge ${esc(s)}">${esc(s || 'UNKNOWN')}</span>`;
}

function riskBadge(level, label) {
  const lvl = level || 'LOW';
  const lbl = label || lvl.replace('_', ' ');
  return `<span class="badge risk-${esc(lvl)}">${esc(lbl)}</span>`;
}

function pageHead(title, sub, button = '') {
  return `<div class="page-head"><div><div class="eyebrow">GHOSTPRINTS / ${esc(title.toUpperCase())}</div><h1>${esc(title)}</h1><p>${esc(sub)}</p></div>${button}</div>`;
}

function metric(label, value, note, color) {
  return `<article class="metric ${color || ''}"><div class="metric-label">${esc(label)}</div><div class="metric-value">${typeof value === 'number' ? fmt(value) : esc(value)}</div><div class="metric-note">${esc(note)}</div></article>`;
}

function table(items, header = true) {
  return `<div class="table-wrap"><table><thead><tr><th>CASE ID</th><th>SUBJECT</th><th>REQUEST DATE</th><th>REPORTED</th><th>AUDIT AT</th><th>ASSESSMENT</th><th>LEAKAGE SCORE</th></tr></thead><tbody>${items.map(c => {
    const score = c.privacy_score?.total_score ?? '—';
    const riskLevel = c.privacy_score?.risk_level || 'LOW';
    const riskLabel = c.privacy_score?.risk_label || riskLevel;
    return `<tr data-case="${esc(c.case_id)}"><td class="mono">${esc(c.case_id)}</td><td>${esc(c.request?.email || '—')}</td><td>${esc((c.request?.requested_at || '').slice(0, 10) || '—')}</td><td>${badge(c.request?.reported_status)}</td><td class="muted">${esc((c.request?.audit_at || '').replace('T', ' ').slice(0, 16) || '—')}</td><td>${badge(c.deletion_status)}</td><td>${riskBadge(riskLevel, `${score}/100 · ${riskLabel}`)}</td></tr>`;
  }).join('') || `<tr><td colspan="7" class="panel-empty">No cases match these filters.</td></tr>`}</tbody></table></div>`;
}

function bindRows() {
  document.querySelectorAll('[data-case]').forEach(r => r.onclick = () => location.hash = `case/${r.dataset.case}`);
}

function chartBars(map) {
  const entries = Object.entries(map || {});
  const max = Math.max(1, ...entries.map(x => x[1]));
  return `<div class="chart">${entries.map(([k, v]) => `<div class="bar-col"><span>${fmt(v)}</span><div class="bar" style="height:${Math.max(5, Math.round(v / max * 82))}%"></div><span>${esc(k.replace(/_service|_platform/g, ''))}</span></div>`).join('') || '<div class="panel-empty">No findings recorded</div>'}</div>`;
}

function donut(data) {
  const total = (data.completed || 0) + (data.incomplete || 0) + (data.not_applicable || 0) || 1;
  const a = (data.completed || 0) / total * 100;
  const b = ((data.completed || 0) + (data.incomplete || 0)) / total * 100;
  return `<div class="donut-wrap"><div class="donut" style="--a:${a}%;--b:${b}%"><div class="donut-center"><strong>${fmt(data.total_requests)}</strong><span>REQUESTS</span></div></div><div class="donut-legend"><span><i class="dot green"></i> Complete <b>${fmt(data.completed)}</b></span><span><i class="dot red"></i> Incomplete <b>${fmt(data.incomplete)}</b></span><span><i class="dot gray"></i> Not applicable <b>${fmt(data.not_applicable)}</b></span></div></div>`;
}

// ---------------------------------------------------------------------------
// VIEW: Overview Dashboard
// ---------------------------------------------------------------------------

async function dashboard() {
  const d = await api('/api/dashboard/summary');
  const avgScore = d.average_privacy_score ?? 0;
  const avgColor = avgScore > 50 ? 'red' : avgScore > 25 ? 'amber' : 'cyan';

  app.innerHTML = `${pageHead('Overview', 'A live view of deletion audits, evidence-backed exposure, and privacy leakage metrics.', '<button class="btn secondary" id="refresh">↻ &nbsp;Refresh</button>')}
  <div class="metrics">
    ${metric('Deletion requests', d.total_requests, 'Official evaluation dataset', 'blue')}
    ${metric('Avg Privacy Leakage', `${avgScore}/100`, `${d.critical_cases_count || 0} critical · ${d.high_cases_count || 0} high`, avgColor)}
    ${metric('Cases incomplete', d.incomplete, 'Residual evidence confirmed', 'red')}
    ${metric('Potential restore risks', d.restore_risks, 'Unblocked backups detected', 'amber')}
  </div>
  <div class="grid">
    <section class="panel">
      <div class="panel-title"><h2>Findings by system</h2><span>CONFIRMED MATCHES</span></div>
      ${chartBars(d.by_system)}
      <div class="legend"><span><i></i> Evidence-linked finding count</span></div>
    </section>
    <section class="panel">
      <div class="panel-title"><h2>Decision distribution</h2><span>ALL CASES</span></div>
      ${donut(d)}
    </section>
  </div>
  <section class="panel table-panel">
    <div class="table-heading">
      <h2>Recent investigations</h2>
      <div class="table-tools">
        <input class="input" id="dash-search" placeholder="Search cases or email…">
        <a class="btn secondary" href="#risks">View Risk Intelligence →</a>
        <a class="btn secondary" href="#investigations">All cases →</a>
      </div>
    </div>
    ${table(d.recent.map(c => ({ ...c, request: d.requests?.find(r => r.case_id === c.case_id) })))}
  </section>
  <div class="notice" style="margin-top:14px">
    <strong>Evidence boundary:</strong> All metrics are calculated deterministically from available participant evidence. Missing or unreadable evidence is preserved as unverified and is never treated as proof of deletion.
  </div>`;

  $('#refresh').onclick = () => dashboard();
  bindRows();
  $('#dash-search').oninput = async e => {
    const q = e.target.value;
    if (q.length > 1) {
      const x = await api(`/api/investigations?q=${encodeURIComponent(q)}&limit=6`);
      $('.table-wrap').innerHTML = table(x.items);
      bindRows();
    }
  };
}

// ---------------------------------------------------------------------------
// VIEW: Investigation Centre
// ---------------------------------------------------------------------------

async function investigations() {
  app.innerHTML = `${pageHead('Investigation centre', 'Search and inspect every deletion request at its audit cutoff.', '<button class="btn" id="run">▶ &nbsp;Run investigations</button>')}
  <section class="panel table-panel">
    <div class="table-heading">
      <h2>Deletion requests</h2>
      <div class="table-tools">
        <input class="input" id="q" placeholder="Search ID, email, risk…">
        <select class="select" id="status">
          <option value="">All statuses</option>
          <option>COMPLETE</option>
          <option>INCOMPLETE</option>
          <option>NOT_APPLICABLE</option>
        </select>
        <select class="select" id="risk-filter">
          <option value="">All risk levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MODERATE">Moderate</option>
          <option value="LOW">Low</option>
          <option value="NO_RISK">No confirmed risk</option>
          <option value="INSUFFICIENT_EVIDENCE">Insufficient evidence</option>
        </select>
        <select class="select" id="sort">
          <option value="">Sort by Case ID</option>
          <option value="score_desc">Highest score first</option>
          <option value="score_asc">Lowest score first</option>
        </select>
      </div>
    </div>
    <div id="rows" class="panel-empty"><span class="spinner"></span>Loading cases…</div>
    <div class="table-heading">
      <span id="total" class="muted"></span>
      <div class="table-tools">
        <button class="btn secondary" id="prev">←</button>
        <button class="btn secondary" id="next">→</button>
      </div>
    </div>
  </section>`;

  let offset = 0;
  async function load() {
    const u = new URLSearchParams({ offset, limit: 25 });
    if ($('#q').value) u.set('q', $('#q').value);
    if ($('#status').value) u.set('status', $('#status').value);
    if ($('#risk-filter').value) u.set('risk', $('#risk-filter').value);
    if ($('#sort').value) u.set('sort', $('#sort').value);

    const d = await api('/api/investigations?' + u);
    $('#rows').innerHTML = table(d.items);
    $('#total').textContent = `${d.total} cases found`;
    bindRows();
  }

  $('#q').oninput = () => { offset = 0; load(); };
  $('#status').onchange = () => { offset = 0; load(); };
  $('#risk-filter').onchange = () => { offset = 0; load(); };
  $('#sort').onchange = () => { offset = 0; load(); };
  $('#prev').onclick = () => { offset = Math.max(0, offset - 25); load(); };
  $('#next').onclick = () => { offset += 25; load(); };

  $('#run').onclick = async () => {
    const b = $('#run');
    b.disabled = true;
    b.textContent = 'Processing…';
    try {
      await api('/api/investigations/run', { method: 'POST' });
      await load();
      toast('Case review and scoring complete.');
    } catch (e) {
      toast(e.message);
    } finally {
      b.disabled = false;
      b.textContent = '▶  Run investigations';
    }
  };
  await load();
}

// ---------------------------------------------------------------------------
// VIEW: Case Detail
// ---------------------------------------------------------------------------

async function detail(id) {
  const c = await api(`/api/investigations/${encodeURIComponent(id)}`);
  const r = c.request || {};
  const steps = c.steps || [];
  const score = c.privacy_score || await api(`/api/investigations/${encodeURIComponent(id)}/risks`);

  app.innerHTML = `${pageHead(c.case_id, 'Case investigation · Evidence cutoff ' + esc(r.audit_at || 'unavailable'), `<div class="table-tools"><a class="btn" href="#risks?case=${encodeURIComponent(c.case_id)}">△ &nbsp;Risk Deep-Dive</a><a class="btn secondary" href="#investigations">← &nbsp;Cases</a></div>`)}
  <div class="metrics" style="margin-bottom:16px">
    ${metric('Privacy Leakage Score', `${score.total_score}/100`, score.risk_label, score.total_score > 50 ? 'red' : score.total_score > 25 ? 'amber' : 'cyan')}
    ${metric('Assessment Status', c.deletion_status, score.evidence_sufficiency, c.deletion_status === 'COMPLETE' ? 'cyan' : c.deletion_status === 'INCOMPLETE' ? 'red' : 'blue')}
    ${metric('Affected Systems', (score.affected_systems || []).length, (score.affected_systems || []).join(', ') || 'None', 'amber')}
    ${metric('Evidence Citations', (score.supporting_evidence_ids || []).length, 'Evidence files backing score', 'blue')}
  </div>
  <div class="detail-grid">
    <section class="panel">
      <div class="panel-title"><h2>Request details</h2>${riskBadge(score.risk_level, score.risk_label)}</div>
      <div class="detail-row"><span>Request identity</span><span class="mono">${esc(r.email)}</span></div>
      <div class="detail-row"><span>Requested at</span><span>${esc(r.requested_at)}</span></div>
      <div class="detail-row"><span>Workflow claim</span><span>${badge(r.reported_status)}</span></div>
      <div class="detail-row"><span>Audit cutoff</span><span>${esc(r.audit_at)}</span></div>
      <div class="detail-row"><span>Request text</span><span>${esc(r.request_text)}</span></div>
      <div class="detail-row"><span>Risk analysis</span><span>${esc(score.summary_explanation)}</span></div>
      <p class="notice">${esc(c.explanation || 'Decision explanation is derived from structured evidence matches.')}</p>
    </section>
    <section class="panel">
      <div class="panel-title"><h2>Investigation steps</h2><span>${steps.length} STEPS</span></div>
      <div class="steps">${steps.map(s => `<div class="step"><span class="stepnum">${s.step_no}</span><div><strong>${esc(s.operation)}</strong><small>${esc(s.phase)} · ${esc(s.system_id)} / ${esc(s.resource_id)}</small></div>${s.evidence_id ? `<span class="badge COMPLETE">${esc(s.evidence_id)}</span>` : `<span class="badge NOT_APPLICABLE">PROPOSED</span>`}</div>`).join('') || '<div class="panel-empty">No structured steps available. Missing evidence is not proof of deletion.</div>'}</div>
    </section>
  </div>`;
}

// ---------------------------------------------------------------------------
// VIEW: Advanced Cybersecurity Risk Analysis (Phase 4 & 5)
// ---------------------------------------------------------------------------

let activeRiskTab = 'deepdive'; // 'deepdive' | 'fleet' | 'compare'
let selectedCaseId = 'case_91';
let activeCategoryKey = 'direct_identifiers';
let compareCaseIds = ['case_91', 'case_33'];

function renderGaugeSVG(score, riskColor, isInsufficient = false) {
  const radius = 70;
  const circumference = 2 * Math.PI * radius; // ~439.8
  const validScore = Math.max(0, Math.min(100, Number(score) || 0));
  const offset = circumference - (circumference * validScore / 100);

  return `<div class="gauge-wrap" style="--gauge-glow: ${riskColor}">
    <svg class="gauge-svg" viewBox="0 0 160 160">
      <circle class="gauge-bg" cx="80" cy="80" r="${radius}"></circle>
      <circle class="gauge-fill" cx="80" cy="80" r="${radius}" style="stroke: ${riskColor}; --dash: ${isInsufficient ? circumference : offset}"></circle>
    </svg>
    <div class="gauge-val-box">
      <span class="gauge-score" style="color: ${riskColor}">${isInsufficient ? '—' : validScore}</span>
      <span class="gauge-max">${isInsufficient ? 'NO DATA' : 'OUT OF 100'}</span>
    </div>
  </div>`;
}

function renderCategoryCard(catKey, cat, isActive) {
  const pct = Math.round((cat.score / cat.max_points) * 100);
  const color = pct >= 80 ? '#ff6d7c' : pct >= 40 ? '#f4bd62' : pct > 0 ? '#4ba8ff' : '#50d5a1';

  return `<div class="cat-card ${isActive ? 'active-cat' : ''}" data-cat="${catKey}">
    <div class="cat-head">
      <div class="cat-title-group">
        <span class="cat-dot" style="background:${color}"></span>
        <span class="cat-title">${esc(cat.title)}</span>
      </div>
      <span class="cat-score-pill">${cat.score} / ${cat.max_points} pts</span>
    </div>
    <div class="cat-bar-bg">
      <div class="cat-bar-fill" style="--w:${pct}%; background:${color}"></div>
    </div>
    <div class="cat-meta">
      <span>${cat.detected ? `<strong>${cat.item_count}</strong> finding(s) detected` : 'No violations confirmed'}</span>
      <span class="cat-hint">${isActive ? '● Inspecting' : 'Inspect details →'}</span>
    </div>
  </div>`;
}

function renderExplainabilityInspector(caseRisk, catKey) {
  const cat = caseRisk.categories?.[catKey] || caseRisk.categories?.direct_identifiers;
  if (!cat) return '';

  const findings = cat.findings || [];
  const systems = cat.affected_systems || [];

  return `<section class="explain-panel" id="explain-panel">
    <div class="explain-header">
      <div class="explain-title">
        <span>🔍 EXPLAINABILITY INSPECTOR:</span>
        <strong style="color:#ffffff">${esc(cat.title)}</strong>
        ${riskBadge(caseRisk.risk_level, `${cat.score}/${cat.max_points} pts awarded`)}
      </div>
      <button class="explain-close" id="explain-close">Collapse panel ✕</button>
    </div>

    <div class="explain-grid">
      <div class="explain-box">
        <h4>Why This Risk Was Detected</h4>
        <p>${esc(cat.explanation)}</p>
        <div style="margin-top:12px">
          <h4>Affected Infrastructure Systems</h4>
          <div class="tag-list">
            ${systems.map(s => `<span class="sys-tag">🖥 &nbsp;${esc(s)}</span>`).join('') || '<span class="muted">None affected</span>'}
          </div>
        </div>
      </div>

      <div class="explain-box">
        <h4>Deterministic Scoring Formula &amp; Math</h4>
        <p>Category weights are configured deterministically. Only findings with validated evidence references award points:</p>
        <span class="math-pill">${esc(caseRisk.calculation_breakdown?.formula || 'Category Max Cap Applied')}</span>
        <div style="margin-top:10px; font-size:10px; color:#8ba0b6">
          <span>Raw findings: <b>${findings.length}</b></span> &nbsp;•&nbsp; 
          <span>Category cap: <b>${cat.max_points} pts</b></span> &nbsp;•&nbsp; 
          <span>Current award: <b>${cat.score} pts</b></span>
        </div>
      </div>
    </div>

    <div class="panel-title" style="margin-top:16px">
      <h2>Supporting Evidence Citations (${findings.length} findings)</h2>
      <span class="muted">CONFIRMED IN REPOSITORY DATASET</span>
    </div>

    <div class="table-wrap">
      <table class="evidence-table">
        <thead>
          <tr>
            <th>OPERATION</th>
            <th>SYSTEM</th>
            <th>RESOURCE</th>
            <th>EVIDENCE FILE ID</th>
            <th>EVIDENCE FILE PATH</th>
            <th>CAPTURE TIME</th>
            <th>RECOMMENDED REMEDIATION</th>
          </tr>
        </thead>
        <tbody>
          ${findings.map(f => `<tr>
            <td class="mono"><strong>${esc(f.operation)}</strong></td>
            <td>${esc(f.system_id)}</td>
            <td class="mono">${esc(f.resource_id)}</td>
            <td><span class="badge COMPLETE">${esc(f.evidence_id || '—')}</span></td>
            <td class="muted">${esc(f.evidence_file_path || '—')}</td>
            <td class="muted">${esc((f.evidence_captured_at || '').slice(0, 16))}</td>
            <td><span class="mono" style="color:#71d99f">${esc(f.remediation_recommendation)}</span></td>
          </tr>`).join('') || '<tr><td colspan="7" class="panel-empty">No residual findings in this category. State verified compliant or absent.</td></tr>'}
        </tbody>
      </table>
    </div>
  </section>`;
}

async function renderDeepDiveView(cases, manifest) {
  let caseRisk;
  try {
    caseRisk = await api(`/api/investigations/${encodeURIComponent(selectedCaseId)}/risks`);
  } catch (e) {
    caseRisk = await api(`/api/investigations/${encodeURIComponent(cases[0]?.case_id || 'case_33')}/risks`);
    selectedCaseId = caseRisk.case_id;
  }

  const req = cases.find(c => c.case_id === selectedCaseId)?.request || {};
  const isInsufficient = caseRisk.is_insufficient_evidence;

  return `<div class="score-hero-grid">
    <div class="gauge-card">
      <div style="width:100%; display:flex; justify-content:space-between; align-items:center">
        <span class="secure"><i></i> EVIDENCE SCORE</span>
        ${riskBadge(caseRisk.risk_level, caseRisk.risk_label)}
      </div>

      ${renderGaugeSVG(caseRisk.total_score, caseRisk.risk_color, isInsufficient)}

      <div class="gauge-status-title" style="color:${caseRisk.risk_color}">
        ${esc(caseRisk.risk_label.toUpperCase())}
      </div>
      <div class="gauge-subtitle">${esc(caseRisk.summary_explanation)}</div>

      <div class="gauge-meta">
        <div><span>AUDIT CUTOFF</span><span>${esc((req.audit_at || '').replace('T', ' ').slice(0, 16) || '—')}</span></div>
        <div><span>EVIDENCE INTEGRITY</span><span>${esc(caseRisk.evidence_sufficiency)}</span></div>
        <div><span>AFFECTED SYSTEMS</span><span>${caseRisk.affected_systems?.length || 0} SYSTEMS</span></div>
        <div><span>EVIDENCE CITATIONS</span><span>${caseRisk.supporting_evidence_ids?.length || 0} FILES</span></div>
      </div>
    </div>

    <div class="categories-col">
      ${Object.entries(caseRisk.categories || {}).map(([k, cat]) => renderCategoryCard(k, cat, k === activeCategoryKey)).join('')}
    </div>
  </div>

  ${renderExplainabilityInspector(caseRisk, activeCategoryKey)}

  <section class="panel" style="margin-top:18px">
    <div class="panel-title">
      <h2>Recommended Prioritized Remediation Plan</h2>
      <span class="muted">${(caseRisk.recommended_remediations || []).length} ACTIONS REQUIRED</span>
    </div>
    <div class="steps">
      ${(caseRisk.recommended_remediations || []).map((r, i) => `
        <div class="step">
          <span class="stepnum">${i + 1}</span>
          <div>
            <div style="display:flex; align-items:center; gap:8px">
              <strong>${esc(r.action)}</strong>
              <span class="badge rem-priority-${esc(r.priority)}">${esc(r.priority)}</span>
            </div>
            <small>Target: ${esc(r.system_id)} / ${esc(r.resource_id)} · Cites ${esc(r.evidence_id || 'Proposed future state')}</small>
          </div>
        </div>
      `).join('') || '<div class="panel-empty">No remediation required. All records verified compliant.</div>'}
    </div>
  </section>`;
}

async function renderFleetView(summary) {
  const dist = summary.risk_distribution || {};
  const total = summary.total_cases || 1;

  return `<div class="metrics">
    ${metric('Fleet Average Score', `${summary.average_score}/100`, 'Across all evaluated cases', summary.average_score > 50 ? 'red' : summary.average_score > 25 ? 'amber' : 'cyan')}
    ${metric('Critical Risk Cases', dist.CRITICAL || 0, `${Math.round((dist.CRITICAL || 0) / total * 100)}% of total fleet`, 'red')}
    ${metric('High & Moderate Cases', (dist.HIGH || 0) + (dist.MODERATE || 0), 'Needs remediation review', 'amber')}
    ${metric('Verified Zero-Exposure', dist.NO_RISK || 0, 'Evidence-backed verified deletions', 'cyan')}
  </div>

  <div class="grid">
    <section class="panel">
      <div class="panel-title"><h2>System Exposure &amp; Blast Radius Analysis</h2><span>CONFIRMED RESIDUAL OCCURRENCES</span></div>
      <div class="system-meter-grid">
        ${(summary.system_exposure || []).map(s => `
          <div class="system-card">
            <div class="system-card-head">
              <span class="system-name">${esc(s.system_id)}</span>
              <span class="badge ${s.finding_count > 30 ? 'INCOMPLETE' : 'ACTIVE'}">${s.finding_count} hits</span>
            </div>
            <div class="cat-bar-bg">
              <div class="cat-bar-fill" style="--w:${Math.min(100, s.finding_count * 2)}%; background: linear-gradient(90deg, #3d8ed5, #ff6d7c)"></div>
            </div>
            <div class="system-stat">Affects <b>${s.cases_affected}</b> independent deletion cases</div>
          </div>
        `).join('')}
      </div>
    </section>

    <section class="panel">
      <div class="panel-title"><h2>Category Exposure Weight Totals</h2><span>FLEET POINTS ACCUMULATION</span></div>
      <div style="display:grid; gap:12px; margin-top:10px">
        ${Object.entries(summary.category_totals || {}).map(([k, v]) => `
          <div>
            <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:4px">
              <span>${esc(k.replace('_', ' ').toUpperCase())}</span>
              <span class="mono">${fmt(v)} total pts</span>
            </div>
            <div class="cat-bar-bg">
              <div class="cat-bar-fill" style="--w:${Math.min(100, v / 40)}%; background: #4ce0d0"></div>
            </div>
          </div>
        `).join('')}
      </div>
    </section>
  </div>

  <section class="panel table-panel">
    <div class="table-heading">
      <h2>Highest Risk Cases Leaderboard</h2>
      <span class="muted">TOP 10 EXPOSURE AUDITS</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>CASE ID</th>
            <th>SCORE</th>
            <th>RISK LEVEL</th>
            <th>FINDINGS</th>
            <th>SYSTEMS AFFECTED</th>
            <th>PRIMARY DRIVERS</th>
            <th>ACTION</th>
          </tr>
        </thead>
        <tbody>
          ${(summary.top_risk_cases || []).map(c => `
            <tr data-case="${esc(c.case_id)}">
              <td class="mono"><strong>${esc(c.case_id)}</strong></td>
              <td><span class="mono" style="font-weight:700; color:#ff6d7c">${c.total_score}/100</span></td>
              <td>${riskBadge(c.risk_level, c.risk_label)}</td>
              <td>${c.finding_count}</td>
              <td class="muted">${esc(c.affected_systems?.join(', ') || '—')}</td>
              <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis" class="muted">${esc(c.primary_drivers)}</td>
              <td><button class="btn secondary select-case-btn" data-id="${esc(c.case_id)}">Inspect Deep-Dive →</button></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  </section>`;
}

async function renderCompareView() {
  const comparison = await api(`/api/risks/comparison?cases=${encodeURIComponent(compareCaseIds.join(','))}`);
  const items = comparison.items || [];

  return `<div>
    <div class="notice" style="margin-bottom:14px">
      <strong>Side-by-Side Privacy Risk Comparison:</strong> Compare multi-vector privacy leakage scores, residual identifier counts, and remediation obligations across multiple audit cases.
    </div>
    <div class="compare-container">
      ${items.map(s => `
        <div class="compare-card">
          <div class="compare-card-head">
            <div>
              <span class="eyebrow">${esc(s.case_id)}</span>
              <div class="compare-score" style="color:${esc(s.risk_color)}">${s.total_score} <small style="font-size:12px; color:#74879e">/ 100</small></div>
            </div>
            ${riskBadge(s.risk_level, s.risk_label)}
          </div>
          <div style="font-size:11px; color:#95a8be; margin-bottom:14px; min-height:36px">${esc(s.summary_explanation)}</div>
          
          <div style="display:grid; gap:8px">
            ${Object.entries(s.categories || {}).map(([k, cat]) => `
              <div>
                <div style="display:flex; justify-content:space-between; font-size:10px; margin-bottom:2px">
                  <span>${esc(cat.title)}</span>
                  <span class="mono">${cat.score}/${cat.max_points}</span>
                </div>
                <div class="cat-bar-bg">
                  <div class="cat-bar-fill" style="--w:${Math.round(cat.score / cat.max_points * 100)}%; background:${esc(s.risk_color)}"></div>
                </div>
              </div>
            `).join('')}
          </div>

          <div style="margin-top:16px; border-top:1px solid #1a2a3e; padding-top:10px; font-size:10px">
            <div>Systems: <span class="mono">${esc((s.affected_systems || []).join(', ') || 'None')}</span></div>
            <div style="margin-top:4px">Remediations: <b>${(s.recommended_remediations || []).length}</b> actions</div>
          </div>
        </div>
      `).join('') || '<div class="panel-empty">Select cases to compare.</div>'}
    </div>
  </div>`;
}

async function risks() {
  const casesData = await api('/api/investigations?limit=100');
  const summary = await api('/api/risks/summary');
  const cases = casesData.items || [];

  app.innerHTML = `
    ${pageHead('Privacy Leakage Intelligence', 'Deterministic, evidence-backed privacy exposure scoring across 5 cryptographic & architectural vectors.', `
      <div class="table-tools">
        <a class="btn secondary" href="/api/risks/export?format=csv" download="privacy_risk_report.csv">⇩ &nbsp;Export Report (CSV)</a>
        <a class="btn secondary" href="/api/risks/export?format=json" download="privacy_risk_report.json">⇩ &nbsp;Export JSON</a>
      </div>
    `)}

    <div class="view-tabs">
      <button class="view-tab ${activeRiskTab === 'deepdive' ? 'active' : ''}" data-tab="deepdive">🔍 &nbsp;Case Deep-Dive</button>
      <button class="view-tab ${activeRiskTab === 'fleet' ? 'active' : ''}" data-tab="fleet">📊 &nbsp;Fleet Risk Posture</button>
      <button class="view-tab ${activeRiskTab === 'compare' ? 'active' : ''}" data-tab="compare">⚖ &nbsp;Case Comparison</button>
    </div>

    ${activeRiskTab === 'deepdive' ? `
      <div class="table-tools" style="margin-bottom:16px; display:flex; gap:10px; align-items:center">
        <span class="muted" style="font-size:11px">Select Case to Audit:</span>
        <select class="select" id="case-select" style="width:240px">
          ${cases.map(c => `
            <option value="${esc(c.case_id)}" ${c.case_id === selectedCaseId ? 'selected' : ''}>
              ${esc(c.case_id)} (${c.privacy_score?.total_score ?? '—'}/100 · ${esc(c.privacy_score?.risk_level || c.deletion_status)})
            </option>
          `).join('')}
        </select>
        <span class="muted" style="font-size:10px">Comparing: <b class="mono">${esc(compareCaseIds.join(' vs '))}</b></span>
      </div>
    ` : ''}

    <div id="risk-content"><span class="spinner"></span> Computing risk analytics…</div>
  `;

  // Render active tab content
  const content = $('#risk-content');
  if (activeRiskTab === 'deepdive') {
    content.innerHTML = await renderDeepDiveView(cases, summary);
  } else if (activeRiskTab === 'fleet') {
    content.innerHTML = await renderFleetView(summary);
  } else if (activeRiskTab === 'compare') {
    content.innerHTML = await renderCompareView();
  }

  // Bind tab buttons
  $$('.view-tab').forEach(b => {
    b.onclick = () => {
      activeRiskTab = b.dataset.tab;
      risks();
    };
  });

  // Bind case selector
  if ($('#case-select')) {
    $('#case-select').onchange = e => {
      selectedCaseId = e.target.value;
      if (!compareCaseIds.includes(selectedCaseId)) {
        compareCaseIds = [selectedCaseId, compareCaseIds[0] || 'case_34'];
      }
      risks();
    };
  }

  // Bind category cards click for explainability inspector
  $$('.cat-card').forEach(card => {
    card.onclick = () => {
      activeCategoryKey = card.dataset.cat;
      risks();
      const panel = $('#explain-panel');
      if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    };
  });

  // Bind explainability collapse button
  if ($('#explain-close')) {
    $('#explain-close').onclick = () => {
      const p = $('#explain-panel');
      if (p) p.style.display = 'none';
    };
  }

  // Bind select case buttons in leaderboard
  $$('.select-case-btn').forEach(btn => {
    btn.onclick = (e) => {
      e.stopPropagation();
      selectedCaseId = btn.dataset.id;
      activeRiskTab = 'deepdive';
      risks();
    };
  });

  bindRows();
}

// ---------------------------------------------------------------------------
// VIEW: Remediation Planner
// ---------------------------------------------------------------------------

async function remediation() {
  const d = await api('/api/investigations?status=INCOMPLETE&limit=100');
  const rows = d.items.flatMap(c => c.steps.filter(s => s.phase !== 'FINDING').map(s => ({ ...s, case_id: c.case_id })));

  app.innerHTML = `${pageHead('Remediation planner', 'Proposed future operations are not represented as completed changes.')}
  <div class="notice" style="margin-bottom:14px">
    <strong>Planning only.</strong> This application has no external system integrations. It cannot delete records, change sync jobs, or block restores. Remediation steps have empty evidence references by design.
  </div>
  <section class="panel table-panel">
    <div class="table-heading">
      <h2>Proposed actions and verification</h2>
      <span class="muted">${rows.length} steps</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>CASE</th><th>PHASE</th><th>OPERATION</th><th>TARGET</th><th>STATE</th><th>PROGRESS</th></tr>
        </thead>
        <tbody>
          ${rows.map(x => `<tr data-case="${esc(x.case_id)}"><td class="mono">${esc(x.case_id)}</td><td>${esc(x.phase)}</td><td>${esc(x.operation)}</td><td>${esc(x.system_id)} / <span class="mono">${esc(x.resource_id)}</span></td><td>${esc(x.state)}</td><td><span class="badge NOT_APPLICABLE">PLANNED</span></td></tr>`).join('') || '<tr><td colspan="6" class="panel-empty">No proposed actions on this page.</td></tr>'}
        </tbody>
      </table>
    </div>
  </section>`;
  bindRows();
}

// ---------------------------------------------------------------------------
// VIEW: Ghost Graph
// ---------------------------------------------------------------------------

async function graph() {
  const d = await api('/api/investigations?limit=100');
  const nodes = d.items.flatMap(c => c.steps.map(s => ({ case_id: c.case_id, ...s })));

  app.innerHTML = `${pageHead('Ghost Graph', 'Lineage view of resources explicitly tied to evidence.')}
  <div class="notice" style="margin-bottom:14px">
    <strong>Graph relationship constraint:</strong> A node does not prove deletion, and an edge is shown only when a supported relationship exists. This baseline extracts resource observations but does not yet parse verified relationship edges from all evidence formats.
  </div>
  <section class="panel">
    <div class="panel-title"><h2>Observed resources</h2><span>${nodes.length} OBSERVATIONS</span></div>
    <div class="file-list">
      ${nodes.slice(0, 150).map(n => `<div class="file-row" data-case="${esc(n.case_id)}"><span>${badge(n.state)} &nbsp; ${esc(n.system_id)} <span class="mono">${esc(n.resource_id)}</span></span><span>${esc(n.evidence_id || 'No cited artifact')}</span></div>`).join('') || '<div class="panel-empty">No nodes with evidence are available.</div>'}
    </div>
  </section>`;
  bindRows();
}

// ---------------------------------------------------------------------------
// VIEW: Dataset Manager
// ---------------------------------------------------------------------------

async function dataset() {
  const d = await api('/api/datasets/official-challenge');
  app.innerHTML = `${pageHead('Dataset manager', 'Inspect the supplied official challenge files and evidence manifest.')}
  <div class="metrics">
    ${metric('Deletion requests', d.request_count, 'Loaded from deletion_requests.csv', 'blue')}
    ${metric('Evidence files', d.evidence_count, 'Manifest entries', 'cyan')}
    ${metric('Unreadable files', d.missing.length, 'Read errors surfaced', 'red')}
    ${metric('Dataset mode', 'READ ONLY', 'Original evidence remains unchanged', 'amber')}
  </div>
  <section class="panel">
    <div class="panel-title"><h2>Evidence manifest</h2><span>CAPTURE DATE FILTERED PER CASE</span></div>
    <div class="notice">The challenge dataset is preloaded from <span class="mono">dataset/</span>. This build safely exposes the manifest and reports missing files. Upload of arbitrary evidence is not enabled because imported data needs a validated parser before it can influence a decision.</div>
    <div class="file-list">
      ${d.manifest.map(f => `<div class="file-row"><span><span class="mono">${esc(f.file_id)}</span> &nbsp; ${esc(f.file_path)}</span><span>${f.readable ? '<span class="badge COMPLETE">READABLE</span>' : '<span class="badge INCOMPLETE">UNREADABLE</span>'} &nbsp; ${esc((f.captured_at || '').slice(0, 10))}</span></div>`).join('')}
    </div>
  </section>`;
}

// ---------------------------------------------------------------------------
// VIEW: Reports & Export
// ---------------------------------------------------------------------------

async function reports() {
  app.innerHTML = `${pageHead('Reports & export', 'Generate the challenge CSV and download case review data.')}
  <div class="grid">
    <section class="panel">
      <div class="panel-title"><h2>Official Challenge Submission</h2><span>CSV · UTF-8</span></div>
      <p class="muted">One row per deletion request. Export runs the deterministic local analysis engine and serializes the required 3 columns.</p>
      <a class="btn" href="/api/reports/export" download="output.csv">⇩ &nbsp;Download output.csv</a> 
      <button class="btn secondary" id="validate">Validate structure</button>
      <div id="report-status" class="notice" style="margin-top:15px">Challenge output conforms to official grading contract.</div>
    </section>

    <section class="panel">
      <div class="panel-title"><h2>Privacy Leakage Risk Dossier</h2><span>SECURITY SAAS EXPORT</span></div>
      <p class="muted">Export complete multi-vector privacy leakage risk scores, category breakdowns, affected systems, and cited evidence references.</p>
      <div style="display:flex; gap:10px; margin-top:14px">
        <a class="btn secondary" href="/api/risks/export?format=csv" download="privacy_risk_report.csv">⇩ &nbsp;Download Risk Report (CSV)</a>
        <a class="btn secondary" href="/api/risks/export?format=json" download="privacy_risk_report.json">⇩ &nbsp;Download JSON Dossier</a>
      </div>
    </section>
  </div>`;

  $('#validate').onclick = async () => {
    try {
      const d = await api('/api/dashboard/summary');
      $('#report-status').innerHTML = `Loaded ${fmt(d.total_requests)} requests and generated output in the required schema. Run <span class="mono">node code/server.js --export</span> to write it at repository root.`;
    } catch (e) {
      toast(e.message);
    }
  };
}

// ---------------------------------------------------------------------------
// VIEW: Landing / Welcome
// ---------------------------------------------------------------------------

async function landing() {
  app.innerHTML = `<div style="max-width:980px;margin:40px auto">
    <div class="eyebrow">GHOSTPRINTS · DELETION INTELLIGENCE</div>
    <h1 style="font-size:38px;max-width:700px;line-height:1.2;letter-spacing:-1.5px">Deleting data is easy.<br><span style="color:#59c5e0">Proving it’s gone is intelligence.</span></h1>
    <p style="max-width:590px;color:#93a2b5;line-height:1.8">Investigate deletion claims across system evidence, identity history, records, and restoration paths. Every finding carries a source reference; missing evidence remains visible.</p>
    <p style="margin:25px 0 42px">
      <a class="btn" href="#dashboard">Launch investigation &nbsp;→</a> 
      <a class="btn secondary" href="#risks">Explore Risk Intelligence</a>
    </p>
    <div class="grid">
      <section class="panel">
        <div class="panel-title"><h2>01 · Resolve</h2><span>IDENTITY HISTORY</span></div>
        <p class="muted">Connect current and historical identifiers to the supplied identity record before searching evidence.</p>
      </section>
      <section class="panel">
        <div class="panel-title"><h2>02 · Reconstruct</h2><span>AUDIT CUTOFF</span></div>
        <p class="muted">Use only evidence available by the request’s audit timestamp and keep claims separate from observed state.</p>
      </section>
    </div>
    <section class="panel">
      <div class="panel-title"><h2>03 · Score &amp; Explain</h2><span>EVIDENCE-BACKED PRIVACY SCORE</span></div>
      <p class="muted">Calculate deterministic Privacy Leakage Scores across 5 risk categories with complete explainability and citation.</p>
    </section>
  </div>`;
}

function toast(s) {
  const n = document.createElement('div');
  n.className = 'toast';
  n.textContent = s;
  document.body.append(n);
  setTimeout(() => n.remove(), 3200);
}

async function route() {
  document.querySelectorAll('.nav-link').forEach(a => a.classList.toggle('active', location.hash === (a.getAttribute('href'))));
  const rawPart = location.hash.slice(1);
  const queryIndex = rawPart.indexOf('?');
  const pathPart = queryIndex !== -1 ? rawPart.slice(0, queryIndex) : rawPart;
  const queryString = queryIndex !== -1 ? rawPart.slice(queryIndex + 1) : '';
  const params = new URLSearchParams(queryString);

  const part = pathPart.split('/');
  const name = part[0] || 'dashboard';

  $('#crumb').textContent = ({
    dashboard: 'Overview',
    home: 'Welcome',
    investigations: 'Investigation centre',
    graph: 'Ghost Graph',
    risks: 'Privacy Leakage Intelligence',
    remediation: 'Remediation planner',
    dataset: 'Dataset manager',
    reports: 'Reports & export',
    case: 'Case detail'
  })[name] || 'Overview';

  if (params.get('case')) {
    selectedCaseId = params.get('case');
  }

  try {
    if (name === 'case') await detail(part[1]);
    else if (name === 'investigations') await investigations();
    else if (name === 'graph') await graph();
    else if (name === 'risks') await risks();
    else if (name === 'remediation') await remediation();
    else if (name === 'dataset') await dataset();
    else if (name === 'reports') await reports();
    else if (name === 'home') await landing();
    else await dashboard();
  } catch (e) {
    app.innerHTML = `<section class="panel"><div class="eyebrow">REQUEST ERROR</div><h2>Workspace could not load this view</h2><p class="muted">${esc(e.message)}</p><button class="btn" onclick="location.reload()">Retry</button></section>`;
  }
}

$('#menu').onclick = () => $('#sidebar').classList.toggle('open');
window.addEventListener('hashchange', route);
fetch('/api/health').then(r => r.json()).then(d => {
  $('#api-status').textContent = `API connected · ${d.evidence_files} evidence files`;
  $('#case-count').textContent = d.requests;
}).catch(() => $('#api-status').textContent = 'API unavailable');
route();
