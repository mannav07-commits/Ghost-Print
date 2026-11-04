const test = require('node:test');
const assert = require('node:assert/strict');
const {
  calculatePrivacyLeakageScore,
  calculateAggregateRiskSummary,
  dedupeFindings,
  DEFAULT_CONFIG,
  RISK_LEVELS,
} = require('../privacy-score');

test('Scenario 1: No residual findings with sufficient evidence -> Score 0, NO_RISK', () => {
  const caseData = {
    case_id: 'case_complete_01',
    deletion_status: 'COMPLETE',
    steps: [
      { step_no: 1, phase: 'VERIFICATION', system_id: 'account_service', resource_id: 'account_001', operation: 'VERIFY_RECORD_ABSENT', state: 'ABSENT', evidence_id: 'evidence_54' }
    ],
  };
  const result = calculatePrivacyLeakageScore(caseData);
  assert.equal(result.total_score, 0);
  assert.equal(result.risk_level, 'NO_RISK');
  assert.equal(result.evidence_sufficiency, 'SUFFICIENT');
  assert.equal(result.is_insufficient_evidence, false);
});

test('Scenario 2: Direct identifiers remaining -> Max 30 points applied', () => {
  const caseData = {
    case_id: 'case_direct_ids',
    deletion_status: 'INCOMPLETE',
    steps: [
      { step_no: 1, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_101', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'evidence_01' },
      { step_no: 2, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_102', operation: 'REPORT_EXPOSED_PII', state: 'PRESENT', evidence_id: 'evidence_02' },
      { step_no: 3, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_103', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'evidence_03' },
    ],
  };
  const result = calculatePrivacyLeakageScore(caseData);
  assert.equal(result.categories.direct_identifiers.score, 30); // 3 items * 15 = 45, capped at 30
  assert.equal(result.categories.direct_identifiers.detected, true);
  assert.equal(result.categories.direct_identifiers.item_count, 3);
});

test('Scenario 3: Sensitive information remaining -> Max 25 points applied', () => {
  const caseData = {
    case_id: 'case_sensitive',
    deletion_status: 'INCOMPLETE',
    steps: [
      { step_no: 1, phase: 'FINDING', system_id: 'support_platform', resource_id: 'support_401', operation: 'REPORT_EXPOSED_PII', state: 'PRESENT', evidence_id: 'evidence_04' },
      { step_no: 2, phase: 'FINDING', system_id: 'analytics_platform', resource_id: 'analytics_802', operation: 'REPORT_EXPOSED_PII', state: 'PRESENT', evidence_id: 'evidence_05' },
      { step_no: 3, phase: 'FINDING', system_id: 'support_platform', resource_id: 'attachment_901', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'evidence_06' },
    ],
  };
  const result = calculatePrivacyLeakageScore(caseData);
  assert.equal(result.categories.sensitive_info.score, 25); // 12 + 10 + 12 = 34, capped at 25
  assert.equal(result.categories.sensitive_info.detected, true);
});

test('Scenario 4: Active data flows -> Max 20 points applied', () => {
  const caseData = {
    case_id: 'case_active_flows',
    deletion_status: 'INCOMPLETE',
    steps: [
      { step_no: 1, phase: 'FINDING', system_id: 'integration_service', resource_id: 'data_flow_901', operation: 'REPORT_ACTIVE_DATA_FLOW', state: 'ACTIVE', evidence_id: 'evidence_07' },
      { step_no: 2, phase: 'FINDING', system_id: 'integration_service', resource_id: 'data_flow_902', operation: 'REPORT_ACTIVE_DATA_FLOW', state: 'ACTIVE', evidence_id: 'evidence_08' },
    ],
  };
  const result = calculatePrivacyLeakageScore(caseData);
  assert.equal(result.categories.active_flows.score, 20); // 2 * 10 = 20
  assert.equal(result.categories.active_flows.detected, true);
});

test('Scenario 5: Backup exposure -> Max 15 points applied', () => {
  const caseData = {
    case_id: 'case_backup',
    deletion_status: 'INCOMPLETE',
    steps: [
      { step_no: 1, phase: 'FINDING', system_id: 'backup_service', resource_id: 'backup_301', operation: 'REPORT_RESTORE_RISK', state: 'ACTIVE', evidence_id: 'evidence_09' },
      { step_no: 2, phase: 'FINDING', system_id: 'backup_service', resource_id: 'archive_302', operation: 'REPORT_RESTORE_RISK', state: 'ACTIVE', evidence_id: 'evidence_10' },
    ],
  };
  const result = calculatePrivacyLeakageScore(caseData);
  assert.equal(result.categories.backup_exposure.score, 15); // 10 + 5 = 15
  assert.equal(result.categories.backup_exposure.detected, true);
});

test('Scenario 6: Multiple affected systems -> Correct blast radius points applied', () => {
  // 1 system = 2 pts, 2 = 5 pts, 3 = 8 pts, 4+ = 10 pts
  const case1Sys = {
    case_id: 'case_1sys',
    deletion_status: 'INCOMPLETE',
    steps: [
      { step_no: 1, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_1', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'ev_1' }
    ]
  };
  assert.equal(calculatePrivacyLeakageScore(case1Sys).categories.system_spread.score, 2);

  const case4Sys = {
    case_id: 'case_4sys',
    deletion_status: 'INCOMPLETE',
    steps: [
      { step_no: 1, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_1', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'ev_1' },
      { step_no: 2, phase: 'FINDING', system_id: 'search_service', resource_id: 'search_1', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'ev_2' },
      { step_no: 3, phase: 'FINDING', system_id: 'support_platform', resource_id: 'support_1', operation: 'REPORT_EXPOSED_PII', state: 'PRESENT', evidence_id: 'ev_3' },
      { step_no: 4, phase: 'FINDING', system_id: 'backup_service', resource_id: 'backup_1', operation: 'REPORT_RESTORE_RISK', state: 'ACTIVE', evidence_id: 'ev_4' },
    ]
  };
  assert.equal(calculatePrivacyLeakageScore(case4Sys).categories.system_spread.score, 10);
});

test('Scenario 7: Duplicate findings are deduplicated without double-counting', () => {
  const caseWithDupes = {
    case_id: 'case_dupes',
    deletion_status: 'INCOMPLETE',
    steps: [
      { step_no: 1, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_001', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'evidence_01' },
      { step_no: 2, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_001', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'evidence_01' }, // Duplicate
    ]
  };
  const result = calculatePrivacyLeakageScore(caseWithDupes);
  assert.equal(result.calculation_breakdown.raw_finding_count, 2);
  assert.equal(result.calculation_breakdown.deduped_finding_count, 1);
  assert.equal(result.categories.direct_identifiers.score, 15); // Only counted once
});

test('Scenario 8: Missing evidence marked as INSUFFICIENT_EVIDENCE not 0/No Risk', () => {
  const caseMissingEvidence = {
    case_id: 'case_missing',
    deletion_status: 'INCOMPLETE',
    missing_evidence: true,
    steps: [], // 0 findings because evidence was missing
  };
  const result = calculatePrivacyLeakageScore(caseMissingEvidence);
  assert.equal(result.total_score, 0);
  assert.equal(result.risk_level, 'INSUFFICIENT_EVIDENCE');
  assert.equal(result.evidence_sufficiency, 'INSUFFICIENT_EVIDENCE');
  assert.equal(result.is_insufficient_evidence, true);
  assert.match(result.summary_explanation, /missing or unreadable/i);
});

test('Scenario 9: Incomplete investigation with findings assigns valid risk level', () => {
  const caseIncomplete = {
    case_id: 'case_inc',
    deletion_status: 'INCOMPLETE',
    steps: [
      { step_no: 1, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_005', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'evidence_54' }
    ]
  };
  const result = calculatePrivacyLeakageScore(caseIncomplete);
  assert.equal(result.total_score, 17); // 15 (direct) + 2 (1 system) = 17
  assert.equal(result.risk_level, 'LOW');
  assert.equal(result.affected_systems.length, 1);
  assert.equal(result.recommended_remediations.length, 1);
});

test('Scenario 10: Maximum risk scenario capped at exactly 100', () => {
  const caseMax = {
    case_id: 'case_max',
    deletion_status: 'INCOMPLETE',
    steps: [
      // Direct (30 max)
      { step_no: 1, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_1', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'e1' },
      { step_no: 2, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_2', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'e2' },
      // Sensitive (25 max)
      { step_no: 3, phase: 'FINDING', system_id: 'support_platform', resource_id: 'support_1', operation: 'REPORT_EXPOSED_PII', state: 'PRESENT', evidence_id: 'e3' },
      { step_no: 4, phase: 'FINDING', system_id: 'analytics_platform', resource_id: 'analytics_1', operation: 'REPORT_EXPOSED_PII', state: 'PRESENT', evidence_id: 'e4' },
      { step_no: 5, phase: 'FINDING', system_id: 'export_service', resource_id: 'export_1', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'e5' },
      // Active Flows (20 max)
      { step_no: 6, phase: 'FINDING', system_id: 'integration_service', resource_id: 'data_flow_1', operation: 'REPORT_ACTIVE_DATA_FLOW', state: 'ACTIVE', evidence_id: 'e6' },
      { step_no: 7, phase: 'FINDING', system_id: 'integration_service', resource_id: 'data_flow_2', operation: 'REPORT_ACTIVE_DATA_FLOW', state: 'ACTIVE', evidence_id: 'e7' },
      // Backup Exposure (15 max)
      { step_no: 8, phase: 'FINDING', system_id: 'backup_service', resource_id: 'backup_1', operation: 'REPORT_RESTORE_RISK', state: 'ACTIVE', evidence_id: 'e8' },
      { step_no: 9, phase: 'FINDING', system_id: 'backup_service', resource_id: 'archive_1', operation: 'REPORT_RESTORE_RISK', state: 'ACTIVE', evidence_id: 'e9' },
      // 5 systems -> 10 max
    ]
  };
  const result = calculatePrivacyLeakageScore(caseMax);
  assert.equal(result.categories.direct_identifiers.score, 30);
  assert.equal(result.categories.sensitive_info.score, 25);
  assert.equal(result.categories.active_flows.score, 20);
  assert.equal(result.categories.backup_exposure.score, 15);
  assert.equal(result.categories.system_spread.score, 10);
  assert.equal(result.total_score, 100);
  assert.equal(result.risk_level, 'CRITICAL');
});

test('Aggregate risk summary calculates fleet metrics correctly', () => {
  const cases = [
    { case_id: 'case_1', deletion_status: 'COMPLETE', steps: [] },
    { case_id: 'case_2', deletion_status: 'INCOMPLETE', steps: [
      { step_no: 1, phase: 'FINDING', system_id: 'account_service', resource_id: 'account_1', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', evidence_id: 'e1' }
    ] }
  ];
  const summary = calculateAggregateRiskSummary(cases, [], []);
  assert.equal(summary.total_cases, 2);
  assert.equal(summary.risk_distribution.NO_RISK, 1);
  assert.equal(summary.risk_distribution.LOW, 1);
  assert.equal(summary.average_score, 9); // (0 + 17) / 2 = 8.5 -> 9
  assert.equal(summary.system_exposure.length, 1);
  assert.equal(summary.system_exposure[0].system_id, 'account_service');
});

