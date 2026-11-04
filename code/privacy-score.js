/**
 * privacy-score.js - Advanced Evidence-Based Privacy Leakage Score Engine for Ghost-Print.
 * 
 * Provides deterministic, explainable, evidence-backed scoring (0-100)
 * across 5 risk categories with strict deduplication and evidence sufficiency guards.
 */

const DEFAULT_CONFIG = {
  weights: {
    direct_identifiers: 30,
    sensitive_info: 25,
    active_flows: 20,
    backup_exposure: 15,
    system_spread: 10,
  },
  thresholds: {
    LOW_MAX: 25,
    MODERATE_MAX: 50,
    HIGH_MAX: 75,
  },
  rates: {
    direct_identifier_per_item: 15,
    sensitive_support_per_item: 12,
    sensitive_telemetry_per_item: 10,
    active_flow_per_item: 10,
    backup_primary_item: 10,
    backup_additional_item: 5,
    system_spread_curve: { 0: 0, 1: 2, 2: 5, 3: 8, 4: 10 },
  },
};

const RISK_LEVELS = {
  NOT_APPLICABLE: { id: 'NOT_APPLICABLE', label: 'Not Applicable', color: '#8190a5', badgeClass: 'NOT_APPLICABLE' },
  NO_RISK: { id: 'NO_RISK', label: 'No Confirmed Exposure', color: '#50d5a1', badgeClass: 'COMPLETE' },
  INSUFFICIENT_EVIDENCE: { id: 'INSUFFICIENT_EVIDENCE', label: 'Insufficient Evidence', color: '#f4bd62', badgeClass: 'ACTIVE' },
  LOW: { id: 'LOW', label: 'Low Risk', color: '#4ba8ff', badgeClass: 'blue' },
  MODERATE: { id: 'MODERATE', label: 'Moderate Risk', color: '#f4bd62', badgeClass: 'amber' },
  HIGH: { id: 'HIGH', label: 'High Risk', color: '#ff9854', badgeClass: 'amber' },
  CRITICAL: { id: 'CRITICAL', label: 'Critical Risk', color: '#ff6d7c', badgeClass: 'INCOMPLETE' },
};

/**
 * Deduplicate findings by system, resource, operation, and evidence.
 */
function dedupeFindings(findings = []) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const key = [f.system_id || f.system, f.resource_id || f.resource, f.operation || f.op, f.evidence_id || f.evidence].join('|');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

/**
 * Normalize finding structure
 */
function normalizeFinding(f, evidenceMap = new Map()) {
  const systemId = f.system_id || f.system || 'unknown';
  const resourceId = f.resource_id || f.resource || 'unknown';
  const operation = f.operation || f.op || 'REPORT_REMAINING_RECORD';
  const state = f.state || 'PRESENT';
  const evidenceId = f.evidence_id || f.evidence || '';
  const evidenceMeta = evidenceMap.get(evidenceId) || null;

  return {
    system_id: systemId,
    resource_id: resourceId,
    operation,
    state,
    evidence_id: evidenceId,
    category: f.category || '',
    evidence_file_path: evidenceMeta?.file_path || '',
    evidence_origin: evidenceMeta?.origin || '',
    evidence_captured_at: evidenceMeta?.captured_at || '',
    remediation_recommendation: getRemediationRecommendation(operation, resourceId, systemId),
  };
}

/**
 * Maps finding operation to recommended remediation action
 */
function getRemediationRecommendation(operation, resourceId, systemId) {
  switch (operation) {
    case 'REPORT_ACTIVE_DATA_FLOW':
      return `Execute DISABLE_DATA_FLOW on ${systemId} (${resourceId}) and verify flow termination.`;
    case 'REPORT_RESTORE_RISK':
      return `Execute BLOCK_RESTORE on ${systemId} (${resourceId}) to prevent historic revival.`;
    case 'REPORT_EXPOSED_PII':
      return `Execute REDACT_RECORD or ANONYMIZE_RECORD on ${systemId} (${resourceId}) removing direct identifiers.`;
    case 'REPORT_REMAINING_RECORD':
    default:
      return `Execute DELETE_RECORD on ${systemId} (${resourceId}) and verify absence in primary and replica stores.`;
  }
}

/**
 * Evaluates the 5 category scores from deduplicated findings.
 */
function evaluateCategories(findings, config = DEFAULT_CONFIG) {
  const weights = config.weights;
  const rates = config.rates;

  // A. Direct Identifiers
  // USER_PROFILE, account_*, SEARCH_INDEX_ENTRY with direct identity tokens
  const directFindings = findings.filter(f =>
    f.operation === 'REPORT_REMAINING_RECORD' &&
    (/USER_PROFILE|customer_profile|account/i.test(f.category) || /account_/i.test(f.resource_id)) ||
    (f.operation === 'REPORT_EXPOSED_PII' && /account_|user_/i.test(f.resource_id))
  );
  const directScore = Math.min(weights.direct_identifiers, directFindings.length * rates.direct_identifier_per_item);

  // B. Sensitive Personal Information
  // Support messages/attachments, telemetry, analytics, exports
  const sensitiveFindings = findings.filter(f =>
    /SUPPORT_MESSAGE|SUPPORT_ATTACHMENT|ANALYTICS_PROFILE|PRODUCT_TELEMETRY|USER_EXPORT/i.test(f.category) ||
    /support_|attachment_|analytics_|telemetry_|export_/i.test(f.resource_id) ||
    (f.operation === 'REPORT_EXPOSED_PII' && !directFindings.includes(f))
  );
  let sensitiveRaw = 0;
  for (const f of sensitiveFindings) {
    if (/support_|attachment_|SUPPORT/i.test(f.resource_id + f.category)) {
      sensitiveRaw += rates.sensitive_support_per_item;
    } else {
      sensitiveRaw += rates.sensitive_telemetry_per_item;
    }
  }
  const sensitiveScore = Math.min(weights.sensitive_info, sensitiveRaw);

  // C. Active Data Flows
  const activeFlowFindings = findings.filter(f =>
    f.operation === 'REPORT_ACTIVE_DATA_FLOW' ||
    (/data_flow_|sync_|connector_/i.test(f.resource_id) && f.state === 'ACTIVE')
  );
  const activeFlowScore = Math.min(weights.active_flows, activeFlowFindings.length * rates.active_flow_per_item);

  // D. Backup and Restoration Exposure
  const backupFindings = findings.filter(f =>
    f.operation === 'REPORT_RESTORE_RISK' ||
    (/backup_|archive_|replica_/i.test(f.resource_id) && f.state === 'ACTIVE')
  );
  let backupScore = 0;
  if (backupFindings.length === 1) {
    backupScore = rates.backup_primary_item;
  } else if (backupFindings.length >= 2) {
    backupScore = Math.min(weights.backup_exposure, rates.backup_primary_item + (backupFindings.length - 1) * rates.backup_additional_item);
  }

  // E. Multiple Systems Retaining Information
  const affectedSystems = Array.from(new Set(findings.map(f => f.system_id).filter(Boolean)));
  const sysCount = affectedSystems.length;
  const spreadCurve = rates.system_spread_curve;
  const systemSpreadScore = sysCount >= 4 ? spreadCurve[4] : (spreadCurve[sysCount] ?? 0);

  return {
    direct_identifiers: {
      category_id: 'direct_identifiers',
      title: 'Remaining Direct Identifiers',
      score: directScore,
      max_points: weights.direct_identifiers,
      detected: directFindings.length > 0,
      item_count: directFindings.length,
      findings: directFindings,
      affected_systems: Array.from(new Set(directFindings.map(f => f.system_id))),
      explanation: directFindings.length > 0
        ? `Found ${directFindings.length} unpurged profile/account record(s) containing direct customer identity tokens.`
        : 'No unpurged direct identity profiles were confirmed in evidence.',
    },
    sensitive_info: {
      category_id: 'sensitive_info',
      title: 'Sensitive Personal Information',
      score: sensitiveScore,
      max_points: weights.sensitive_info,
      detected: sensitiveFindings.length > 0,
      item_count: sensitiveFindings.length,
      findings: sensitiveFindings,
      affected_systems: Array.from(new Set(sensitiveFindings.map(f => f.system_id))),
      explanation: sensitiveFindings.length > 0
        ? `Detected ${sensitiveFindings.length} residual record(s) with customer communications, support attachments, or analytics telemetry.`
        : 'No un-anonymized customer telemetry, exports, or support messages confirmed.',
    },
    active_flows: {
      category_id: 'active_flows',
      title: 'Active Data Flows',
      score: activeFlowScore,
      max_points: weights.active_flows,
      detected: activeFlowFindings.length > 0,
      item_count: activeFlowFindings.length,
      findings: activeFlowFindings,
      affected_systems: Array.from(new Set(activeFlowFindings.map(f => f.system_id))),
      explanation: activeFlowFindings.length > 0
        ? `Identified ${activeFlowFindings.length} active process(es) or data connectors capable of recreating or synchronizing customer data.`
        : 'No active synchronization jobs or data replication pipelines detected.',
    },
    backup_exposure: {
      category_id: 'backup_exposure',
      title: 'Backup & Restoration Exposure',
      score: backupScore,
      max_points: weights.backup_exposure,
      detected: backupFindings.length > 0,
      item_count: backupFindings.length,
      findings: backupFindings,
      affected_systems: Array.from(new Set(backupFindings.map(f => f.system_id))),
      explanation: backupFindings.length > 0
        ? `Identified ${backupFindings.length} restorable backup image(s) or failover replica snapshot(s) lacking restoration blockades.`
        : 'No unblocked backup restoration vectors identified in evidence.',
    },
    system_spread: {
      category_id: 'system_spread',
      title: 'Multiple Systems Retaining Information',
      score: systemSpreadScore,
      max_points: weights.system_spread,
      detected: sysCount > 1,
      item_count: sysCount,
      findings: [],
      affected_systems: affectedSystems,
      explanation: sysCount > 1
        ? `Residual data is distributed across ${sysCount} distinct infrastructure systems, multiplying breach blast radius.`
        : (sysCount === 1 ? 'Residual data is localized within a single system.' : 'No system retains confirmed residual data.'),
    },
  };
}

/**
 * Determine risk level based on total score and investigation status.
 */
function determineRiskLevel(score, status, hasInsufficientEvidence, config = DEFAULT_CONFIG) {
  if (status === 'NOT_APPLICABLE') {
    return RISK_LEVELS.NOT_APPLICABLE;
  }
  if (hasInsufficientEvidence) {
    return RISK_LEVELS.INSUFFICIENT_EVIDENCE;
  }
  if (score === 0) {
    return RISK_LEVELS.NO_RISK;
  }
  if (score <= config.thresholds.LOW_MAX) {
    return RISK_LEVELS.LOW;
  }
  if (score <= config.thresholds.MODERATE_MAX) {
    return RISK_LEVELS.MODERATE;
  }
  if (score <= config.thresholds.HIGH_MAX) {
    return RISK_LEVELS.HIGH;
  }
  return RISK_LEVELS.CRITICAL;
}

/**
 * Main Privacy Leakage Scoring Function
 * 
 * @param {Object} investigationCase - Output from Ghostprints.analyze(req)
 * @param {Object} request - The original deletion request
 * @param {Array|Map} evidenceManifest - Manifest entries for metadata lookup
 * @param {Object} customConfig - Optional weight overrides
 */
function calculatePrivacyLeakageScore(investigationCase, request = {}, evidenceManifest = [], customConfig = {}) {
  const config = { ...DEFAULT_CONFIG, ...customConfig, weights: { ...DEFAULT_CONFIG.weights, ...customConfig.weights } };
  const caseId = investigationCase?.case_id || request?.case_id || 'unknown';
  const deletionStatus = investigationCase?.deletion_status || 'INCOMPLETE';
  const steps = investigationCase?.steps || [];

  // Index evidence manifest for quick metadata retrieval
  const evidenceMap = new Map();
  if (Array.isArray(evidenceManifest)) {
    for (const e of evidenceManifest) evidenceMap.set(e.file_id, e);
  } else if (evidenceManifest instanceof Map) {
    for (const [k, v] of evidenceManifest.entries()) evidenceMap.set(k, v);
  }

  // Extract and deduplicate FINDING steps
  const rawFindings = steps.filter(s => s.phase === 'FINDING');
  const dedupedRaw = dedupeFindings(rawFindings);
  const normalizedFindings = dedupedRaw.map(f => normalizeFinding(f, evidenceMap));

  // Check evidence sufficiency
  // A case is marked insufficient if deletion is incomplete AND 0 findings exist because evidence was missing/unreadable
  const isMissingEvidence = Boolean(investigationCase?.missing_evidence) ||
    (deletionStatus === 'INCOMPLETE' && normalizedFindings.length === 0);

  const evidenceSufficiency = deletionStatus === 'NOT_APPLICABLE'
    ? 'NOT_APPLICABLE'
    : (isMissingEvidence ? 'INSUFFICIENT_EVIDENCE' : 'SUFFICIENT');

  // If NOT_APPLICABLE (request was not a deletion request)
  if (deletionStatus === 'NOT_APPLICABLE') {
    const categories = evaluateCategories([], config);
    return {
      case_id: caseId,
      investigation_status: deletionStatus,
      total_score: 0,
      risk_level: RISK_LEVELS.NOT_APPLICABLE.id,
      risk_label: RISK_LEVELS.NOT_APPLICABLE.label,
      risk_color: RISK_LEVELS.NOT_APPLICABLE.color,
      badge_class: RISK_LEVELS.NOT_APPLICABLE.badgeClass,
      evidence_sufficiency: evidenceSufficiency,
      is_insufficient_evidence: false,
      summary_explanation: 'Request does not authorize deletion; privacy leakage score is not applicable.',
      categories,
      findings: [],
      affected_systems: [],
      supporting_evidence_ids: [],
      recommended_remediations: [],
      calculation_breakdown: {
        formula: 'Sum(A..E)',
        deduped_finding_count: 0,
        raw_finding_count: 0,
        weights: config.weights,
      },
    };
  }

  // Calculate category-wise scores
  const categories = evaluateCategories(normalizedFindings, config);
  const totalRaw = categories.direct_identifiers.score +
    categories.sensitive_info.score +
    categories.active_flows.score +
    categories.backup_exposure.score +
    categories.system_spread.score;

  const totalScore = Math.min(100, Math.max(0, Math.round(totalRaw)));
  const risk = determineRiskLevel(totalScore, deletionStatus, isMissingEvidence, config);

  // Extract all unique affected systems and evidence IDs
  const allAffectedSystems = Array.from(new Set(normalizedFindings.map(f => f.system_id).filter(Boolean))).sort();
  const supportingEvidenceIds = Array.from(new Set(normalizedFindings.map(f => f.evidence_id).filter(Boolean))).sort();

  // Consolidate remediation actions
  const remediationSet = new Set();
  const recommendedRemediations = [];
  for (const f of normalizedFindings) {
    if (!remediationSet.has(f.remediation_recommendation)) {
      remediationSet.add(f.remediation_recommendation);
      recommendedRemediations.push({
        system_id: f.system_id,
        resource_id: f.resource_id,
        operation: f.operation,
        action: f.remediation_recommendation,
        priority: f.operation === 'REPORT_ACTIVE_DATA_FLOW' ? 'IMMEDIATE' :
                  f.operation === 'REPORT_RESTORE_RISK' ? 'HIGH' : 'NORMAL',
        evidence_id: f.evidence_id,
      });
    }
  }

  // Generate clear summary explanation
  let summaryExplanation = '';
  if (isMissingEvidence) {
    summaryExplanation = 'Investigation is INCOMPLETE: Evidence required to verify absence was missing or unreadable before the audit cutoff. A score of zero does not prove successful deletion.';
  } else if (totalScore === 0 && deletionStatus === 'COMPLETE') {
    summaryExplanation = 'No residual privacy leakage confirmed. All verified records meet retention and deletion policies with supporting evidence.';
  } else {
    const drivers = [];
    if (categories.direct_identifiers.score > 0) drivers.push(`${categories.direct_identifiers.score}pts from remaining direct IDs`);
    if (categories.sensitive_info.score > 0) drivers.push(`${categories.sensitive_info.score}pts from sensitive records`);
    if (categories.active_flows.score > 0) drivers.push(`${categories.active_flows.score}pts from active data flows`);
    if (categories.backup_exposure.score > 0) drivers.push(`${categories.backup_exposure.score}pts from backup restorable risk`);
    if (categories.system_spread.score > 0) drivers.push(`${categories.system_spread.score}pts across ${allAffectedSystems.length} systems`);
    summaryExplanation = `Privacy Leakage Score of ${totalScore}/100 (${risk.label}): Driven by ${drivers.join(', ')}.`;
  }

  return {
    case_id: caseId,
    investigation_status: deletionStatus,
    total_score: totalScore,
    risk_level: risk.id,
    risk_label: risk.label,
    risk_color: risk.color,
    badge_class: risk.badgeClass,
    evidence_sufficiency: evidenceSufficiency,
    is_insufficient_evidence: isMissingEvidence,
    summary_explanation: summaryExplanation,
    categories,
    findings: normalizedFindings,
    affected_systems: allAffectedSystems,
    supporting_evidence_ids: supportingEvidenceIds,
    recommended_remediations: recommendedRemediations,
    calculation_breakdown: {
      formula: 'min(100, direct_identifiers(30) + sensitive_info(25) + active_flows(20) + backup_exposure(15) + system_spread(10))',
      deduped_finding_count: normalizedFindings.length,
      raw_finding_count: rawFindings.length,
      weights: config.weights,
      rates: config.rates,
    },
  };
}

/**
 * Calculates aggregate risk summary across an array of analyzed cases.
 */
function calculateAggregateRiskSummary(analyzedCases = [], requests = [], manifest = []) {
  const scores = analyzedCases.map(c => {
    const req = requests.find(r => r.case_id === c.case_id) || {};
    return calculatePrivacyLeakageScore(c, req, manifest);
  });

  const totalAssessed = scores.length;
  const applicableScores = scores.filter(s => s.investigation_status !== 'NOT_APPLICABLE' && !s.is_insufficient_evidence);
  const avgScore = applicableScores.length
    ? Math.round(applicableScores.reduce((acc, s) => acc + s.total_score, 0) / applicableScores.length)
    : 0;

  const distribution = {
    CRITICAL: scores.filter(s => s.risk_level === 'CRITICAL').length,
    HIGH: scores.filter(s => s.risk_level === 'HIGH').length,
    MODERATE: scores.filter(s => s.risk_level === 'MODERATE').length,
    LOW: scores.filter(s => s.risk_level === 'LOW').length,
    NO_RISK: scores.filter(s => s.risk_level === 'NO_RISK').length,
    INSUFFICIENT_EVIDENCE: scores.filter(s => s.risk_level === 'INSUFFICIENT_EVIDENCE').length,
    NOT_APPLICABLE: scores.filter(s => s.risk_level === 'NOT_APPLICABLE').length,
  };

  // Systems risk frequency and total score contribution
  const systemRiskMap = new Map();
  for (const s of scores) {
    for (const f of s.findings) {
      if (!systemRiskMap.has(f.system_id)) {
        systemRiskMap.set(f.system_id, { system_id: f.system_id, finding_count: 0, cases_affected: new Set() });
      }
      const entry = systemRiskMap.get(f.system_id);
      entry.finding_count++;
      entry.cases_affected.add(s.case_id);
    }
  }

  const systemExposure = Array.from(systemRiskMap.values())
    .map(e => ({
      system_id: e.system_id,
      finding_count: e.finding_count,
      cases_affected: e.cases_affected.size,
    }))
    .sort((a, b) => b.finding_count - a.finding_count);

  // Category totals across fleet
  const categoryTotals = {
    direct_identifiers: scores.reduce((sum, s) => sum + (s.categories?.direct_identifiers?.score || 0), 0),
    sensitive_info: scores.reduce((sum, s) => sum + (s.categories?.sensitive_info?.score || 0), 0),
    active_flows: scores.reduce((sum, s) => sum + (s.categories?.active_flows?.score || 0), 0),
    backup_exposure: scores.reduce((sum, s) => sum + (s.categories?.backup_exposure?.score || 0), 0),
    system_spread: scores.reduce((sum, s) => sum + (s.categories?.system_spread?.score || 0), 0),
  };

  // Top risk cases
  const topRiskCases = [...scores]
    .filter(s => s.total_score > 0)
    .sort((a, b) => b.total_score - a.total_score)
    .slice(0, 10)
    .map(s => ({
      case_id: s.case_id,
      total_score: s.total_score,
      risk_level: s.risk_level,
      risk_label: s.risk_label,
      finding_count: s.findings.length,
      affected_systems: s.affected_systems,
      primary_drivers: s.summary_explanation,
    }));

  return {
    total_cases: totalAssessed,
    average_score: avgScore,
    risk_distribution: distribution,
    category_totals: categoryTotals,
    system_exposure: systemExposure,
    top_risk_cases: topRiskCases,
    weights_configured: DEFAULT_CONFIG.weights,
  };
}

module.exports = {
  DEFAULT_CONFIG,
  RISK_LEVELS,
  calculatePrivacyLeakageScore,
  calculateAggregateRiskSummary,
  dedupeFindings,
  normalizeFinding,
  determineRiskLevel,
};

