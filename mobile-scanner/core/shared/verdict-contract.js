/**
 * shared/verdict-contract.js — Versioned Verdict Contract for VERITY 2.0 (Bharat Shield)
 *
 * Implements a strict, stable, versioned schema contract for cyber fraud and security verdicts.
 * Enforces explicit separation between empirical observations (evidence) and inferential claims,
 * and supports first-class abstention states (UNABLE_TO_DETERMINE, INSUFFICIENT_EVIDENCE).
 *
 * Universal portability: Zero browser extension APIs and zero DOM dependencies.
 */

export const SCHEMA_VERSION = '2.0.0';
export const RULE_PACK_VERSION = '2026.10.1';
export const DETECTOR_ENGINE_VERSION = 'verity-core-2.0.0';

/**
 * Supported input modalities.
 */
export const INPUT_MODALITIES = Object.freeze([
  'url',
  'message',
  'payment_intent',
  'qr',
  'file_download',
  'composite'
]);

/**
 * Normalized threat taxonomy categories based on Indian cyber-fraud scenarios.
 */
export const THREAT_CATEGORIES = Object.freeze([
  'phishing_credential_harvesting',
  'fake_refund_cashback_reward',
  'upi_collect_payment_deception',
  'qr_payment_quishing',
  'brand_impersonation',
  'fake_kyc_account_blocking',
  'courier_parcel_delivery_scam',
  'job_recruitment_task_scam',
  'investment_trading_fraud',
  'loan_credit_advance_fee_scam',
  'government_service_impersonation',
  'fake_shopping_marketplace_scam',
  'tech_support_remote_access_lure',
  'social_engineering_coercion',
  'digital_arrest_extortion',
  'malicious_application_dropper',
  'suspicious_messaging_identity',
  'account_takeover_recovery_scam',
  'benign_legitimate_interaction',
  'unsupported_or_unknown'
]);

/**
 * Standard risk classifications.
 */
export const RISK_CLASSIFICATIONS = Object.freeze([
  'SAFE',
  'CAUTION',
  'HIGH_RISK',
  'ABSTAIN'
]);

/**
 * Explicit abstention reasons when evidence is missing or inconclusive.
 */
export const ABSTENTION_REASONS = Object.freeze([
  'UNABLE_TO_DETERMINE',
  'INSUFFICIENT_EVIDENCE',
  'ANALYSIS_INCOMPLETE',
  'EXTERNAL_CHECK_UNAVAILABLE',
  'UNSUPPORTED_INPUT'
]);

/**
 * Maps risk classifications to legacy actions and severities for backwards compatibility.
 */
const CLASSIFICATION_LEGACY_MAP = {
  SAFE: { action: 'allow', severity: 'safe', state: 'safe' },
  CAUTION: { action: 'warn', severity: 'caution', state: 'caution' },
  HIGH_RISK: { action: 'block', severity: 'danger', state: 'danger' },
  ABSTAIN: { action: 'abstain', severity: 'caution', state: 'inconclusive' }
};

/**
 * Generates a pseudo-random scan identifier.
 * @returns {string} Unique scan ID prefixed with "scn_"
 */
export function generateScanId() {
  const ts = Date.now().toString(36);
  const rnd = Math.random().toString(36).substring(2, 8);
  return `scn_${ts}_${rnd}`;
}

/**
 * Validates whether an object strictly adheres to the Verdict Contract.
 *
 * @param {object} verdict
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateVerdictContract(verdict) {
  const errors = [];

  if (!verdict || typeof verdict !== 'object') {
    return { valid: false, errors: ['Verdict must be a non-null object.'] };
  }

  if (verdict.schemaVersion !== SCHEMA_VERSION) {
    errors.push(`Invalid schemaVersion: expected "${SCHEMA_VERSION}", got "${verdict.schemaVersion}".`);
  }

  if (!verdict.scanId || typeof verdict.scanId !== 'string') {
    errors.push('Missing or invalid scanId string.');
  }

  if (!INPUT_MODALITIES.includes(verdict.inputModality)) {
    errors.push(`Invalid inputModality: "${verdict.inputModality}". Must be one of: ${INPUT_MODALITIES.join(', ')}.`);
  }

  if (!THREAT_CATEGORIES.includes(verdict.threatCategory)) {
    errors.push(`Invalid threatCategory: "${verdict.threatCategory}".`);
  }

  if (!RISK_CLASSIFICATIONS.includes(verdict.riskClassification)) {
    errors.push(`Invalid riskClassification: "${verdict.riskClassification}".`);
  }

  if (typeof verdict.riskScore !== 'number' || verdict.riskScore < 0 || verdict.riskScore > 100) {
    errors.push(`Invalid riskScore: must be a number between 0 and 100, got "${verdict.riskScore}".`);
  }

  if (verdict.riskClassification === 'ABSTAIN') {
    if (!ABSTENTION_REASONS.includes(verdict.abstentionReason)) {
      errors.push(`Abstention verdicts require a valid abstentionReason. Got: "${verdict.abstentionReason}".`);
    }
  }

  if (!Array.isArray(verdict.evidence)) {
    errors.push('verdict.evidence must be an array of observable technical findings.');
  }

  if (!verdict.recommendedAction || typeof verdict.recommendedAction !== 'object') {
    errors.push('verdict.recommendedAction must be an object with safeNextStep guidance.');
  } else if (!verdict.recommendedAction.safeNextStep) {
    errors.push('verdict.recommendedAction.safeNextStep must not be empty.');
  }

  if (!verdict.privacyDisclosure || typeof verdict.privacyDisclosure !== 'object') {
    errors.push('verdict.privacyDisclosure must document telemetry and network lookups.');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Factory to create a fully validated, standardized Verdict object.
 *
 * @param {object} params
 * @param {string} [params.scanId]
 * @param {'url'|'message'|'payment_intent'|'qr'|'file_download'|'composite'} params.inputModality
 * @param {string} params.threatCategory
 * @param {'SAFE'|'CAUTION'|'HIGH_RISK'|'ABSTAIN'} params.riskClassification
 * @param {number} params.riskScore - Clamped 0-100
 * @param {number|null} [params.calibratedConfidence=null] - 0.0 to 1.0 if statistically justified
 * @param {string} [params.abstentionReason=null]
 * @param {Array<{ id: string, description: string, technicalData?: any, source: string }>} [params.evidence=[]]
 * @param {Array<string>} [params.humanExplanations=[]]
 * @param {{ safeNextStep: string, recoveryRoute?: string, emergencyHelpline?: string }} params.recommendedAction
 * @param {{ localOnly: boolean, externalLookups?: Array<{ service: string, transmittedData: string, purpose: string }>, redactionsApplied?: string[] }} [params.privacyDisclosure]
 * @param {Array<string>} [params.knownLimitations=[]]
 * @param {object} [params.metadata={}]
 * @returns {object} Standardized Verdict Contract
 */
export function createVerdict(params) {
  const score = Math.max(0, Math.min(100, Math.round(params.riskScore || 0)));
  const classification = params.riskClassification || (score >= 70 ? 'HIGH_RISK' : (score >= 35 ? 'CAUTION' : 'SAFE'));
  const scanId = params.scanId || generateScanId();
  const legacy = CLASSIFICATION_LEGACY_MAP[classification] || CLASSIFICATION_LEGACY_MAP.SAFE;

  const verdict = {
    schemaVersion: SCHEMA_VERSION,
    scanId,
    timestamp: new Date().toISOString(),
    engineVersions: {
      core: DETECTOR_ENGINE_VERSION,
      rulePack: RULE_PACK_VERSION
    },
    inputModality: params.inputModality || 'composite',
    threatCategory: params.threatCategory || 'unsupported_or_unknown',
    riskClassification: classification,
    riskScore: score,
    calibratedConfidence: typeof params.calibratedConfidence === 'number'
      ? Math.max(0, Math.min(1, params.calibratedConfidence))
      : null,
    abstentionReason: classification === 'ABSTAIN'
      ? (params.abstentionReason || 'INSUFFICIENT_EVIDENCE')
      : null,
    
    // Separation of empirical observation (evidence) vs inference
    evidence: Array.isArray(params.evidence) ? params.evidence : [],
    humanExplanations: Array.isArray(params.humanExplanations) ? params.humanExplanations : [],
    
    // Actionable citizen direction
    recommendedAction: {
      safeNextStep: params.recommendedAction?.safeNextStep || 'Stop and verify before interacting with this content.',
      recoveryRoute: params.recommendedAction?.recoveryRoute || null,
      emergencyHelpline: params.recommendedAction?.emergencyHelpline || '1930'
    },

    // Privacy & processing disclosures
    privacyDisclosure: {
      localOnly: params.privacyDisclosure?.localOnly !== false,
      externalLookups: Array.isArray(params.privacyDisclosure?.externalLookups) ? params.privacyDisclosure.externalLookups : [],
      redactionsApplied: Array.isArray(params.privacyDisclosure?.redactionsApplied) ? params.privacyDisclosure.redactionsApplied : []
    },

    // Transparent uncertainty & boundaries
    uncertainty: {
      hasLimitations: Array.isArray(params.knownLimitations) && params.knownLimitations.length > 0,
      knownLimitations: Array.isArray(params.knownLimitations) ? params.knownLimitations : [],
      isStale: false,
      isDegradedOffline: !!params.metadata?.isDegradedOffline
    },

    // Backwards compatibility layer for existing UI and tests
    legacyCompat: {
      verdict: legacy.severity,
      severity: legacy.severity,
      action: legacy.action,
      score,
      state: legacy.state
    },

    metadata: params.metadata || {}
  };

  const validation = validateVerdictContract(verdict);
  if (!validation.valid) {
    console.warn('[VerdictContract] Schema validation warnings:', validation.errors);
  }

  return verdict;
}

/**
 * Creates an explicit abstention verdict when an input cannot be safely evaluated.
 *
 * @param {string} inputModality
 * @param {'UNABLE_TO_DETERMINE'|'INSUFFICIENT_EVIDENCE'|'ANALYSIS_INCOMPLETE'|'EXTERNAL_CHECK_UNAVAILABLE'|'UNSUPPORTED_INPUT'} reason
 * @param {string} explanation
 * @param {object} [extra={}]
 * @returns {object} Standardized Abstention Verdict
 */
export function createAbstentionVerdict(inputModality, reason, explanation, extra = {}) {
  return createVerdict({
    inputModality,
    threatCategory: 'unsupported_or_unknown',
    riskClassification: 'ABSTAIN',
    riskScore: 25,
    abstentionReason: reason,
    humanExplanations: [explanation || 'Available evidence is insufficient to verify safety with confidence.'],
    recommendedAction: {
      safeNextStep: 'Do not submit credentials, OTPs, or approve payments. Verify through official independent channels.',
      emergencyHelpline: '1930'
    },
    privacyDisclosure: {
      localOnly: true,
      externalLookups: [],
      redactionsApplied: []
    },
    knownLimitations: [
      `Analysis abstained due to ${reason}. The system avoids converting unknown interactions into false assertions of safety.`
    ],
    ...extra
  });
}

export default {
  SCHEMA_VERSION,
  RULE_PACK_VERSION,
  DETECTOR_ENGINE_VERSION,
  INPUT_MODALITIES,
  THREAT_CATEGORIES,
  RISK_CLASSIFICATIONS,
  ABSTENTION_REASONS,
  generateScanId,
  validateVerdictContract,
  createVerdict,
  createAbstentionVerdict
};
