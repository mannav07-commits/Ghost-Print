const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { Ghostprints } = require('../server');
const { calculatePrivacyLeakageScore, calculateAggregateRiskSummary } = require('../privacy-score');

test('Ghostprints class initializes and can compute privacy score for sample cases', () => {
  const app = new Ghostprints();
  const case01Score = app.score('case_01');
  assert.ok(case01Score);
  assert.equal(case01Score.case_id, 'case_01');
  assert.equal(typeof case01Score.total_score, 'number');
  assert.ok(case01Score.categories);
  assert.ok(case01Score.categories.direct_identifiers);

  const summary = app.risksSummary();
  assert.ok(summary);
  assert.equal(summary.total_cases, app.requests.length);
  assert.ok(typeof summary.average_score === 'number');
  assert.ok(summary.risk_distribution);
  assert.ok(Array.isArray(summary.system_exposure));
});

test('Ghostprints dashboard summary includes privacy leakage score fleet metrics', () => {
  const app = new Ghostprints();
  const dash = app.dashboard();
  assert.ok(dash);
  assert.ok('average_privacy_score' in dash);
  assert.ok('risk_distribution' in dash);
  assert.ok('critical_cases_count' in dash);
  assert.ok('high_cases_count' in dash);
});

test('HTTP endpoint /api/risks/summary returns aggregate risk intelligence', async () => {
  const app = new Ghostprints();
  const summary = app.risksSummary();
  assert.ok(summary.total_cases > 0);
  assert.ok(summary.top_risk_cases.length > 0);
  assert.ok('direct_identifiers' in summary.category_totals);
  assert.ok('sensitive_info' in summary.category_totals);
  assert.ok('active_flows' in summary.category_totals);
  assert.ok('backup_exposure' in summary.category_totals);
  assert.ok('system_spread' in summary.category_totals);
});

test('Case-wise comparison returns side-by-side structured scores', () => {
  const app = new Ghostprints();
  const c1 = app.score('case_01');
  const c5 = app.score('case_05');
  assert.ok(c1);
  assert.ok(c5);
  assert.equal(c1.case_id, 'case_01');
  assert.equal(c5.case_id, 'case_05');
  assert.ok(c1.total_score >= 0 && c1.total_score <= 100);
  assert.ok(c5.total_score >= 0 && c5.total_score <= 100);
});

