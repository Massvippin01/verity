/**
 * shared/safe-action-policy.js — Deterministic Bounded Safe Action Engine
 *
 * Implements a strict, deterministic, versioned policy engine that consumes
 * standard Verdict Contract objects (verdict-contract.js) and maps them into
 * bounded, accountable citizen action recommendations and permitted autonomous protections.
 *
 * Design Invariants:
 * 1. Explicit ABSTAIN: Uncertain or inconclusive verdicts NEVER trigger automatic disruption.
 * 2. Never interpret missing evidence as SAFE.
 * 3. Never permit an uncalibrated model to independently authorize a consequential action.
 * 4. Automatic actions are strictly bounded to REVERSIBLE, non-consequential protective interventions
 *    (e.g., pausing an unverified download or defusing an ad-rotator popunder).
 * 5. Irreversible actions (financial account freeze, session revocation, permanent file deletion)
 *    are PROHIBITED from automated execution and require explicit user/institution confirmation.
 * 6. Emits structured audit events suitable for local Flight Recorder ingestion.
 *
 * Universal portability: Zero browser extension API locks; deterministic pure functions.
 */

import { validateVerdictContract } from './verdict-contract.js';

export const POLICY_VERSION = '1.0.0';

/**
 * Standard Action Identifiers
 */
export const ACTION_TYPES = Object.freeze({
  ALLOW_NORMAL: 'ALLOW_NORMAL',
  EXERCISE_CAUTION: 'EXERCISE_CAUTION',
  MANUAL_VERIFY_OFFLINE: 'MANUAL_VERIFY_OFFLINE',
  PAUSE_AND_PROMPT_DOWNLOAD: 'PAUSE_AND_PROMPT_DOWNLOAD',
  DEFUSE_ROGUE_POPUNDER: 'DEFUSE_ROGUE_POPUNDER',
  DISPLAY_SCAM_ACTION_CARD: 'DISPLAY_SCAM_ACTION_CARD',
  RECOMMEND_EMERGENCY_RECOVERY: 'RECOMMEND_EMERGENCY_RECOVERY',
  PROMPT_USER_OVERRIDE: 'PROMPT_USER_OVERRIDE'
});

/**
 * Consequential action categories that are PROHIBITED from automated execution.
 */
export const PROHIBITED_AUTOMATIC_ACTIONS = Object.freeze([
  'BLOCK_BANK_ACCOUNT',
  'INITIATE_CHARGEBACK',
  'REVOKE_ALL_SESSIONS',
  'PERMANENT_DELETE_FILE',
  'SUBMIT_POLICE_COMPLAINT_AUTOMATIC',
  'CANCEL_UPI_MANDATE_SILENTLY'
]);

/**
 * Deterministically generates an evaluation ID.
 */
function generatePolicyEvaluationId(scanId) {
  const ts = Date.now().toString(36);
  return `pol_${scanId ? scanId.replace(/^scn_/, '') : ts}_${Math.random().toString(36).substring(2, 6)}`;
}

/**
 * Evaluates the Safe Action Policy against a validated Verdict Contract.
 *
 * @param {object} verdict - Valid Verdict Contract object (schema 2.0.0)
 * @param {object} [context={}] - Evaluation context (platform capabilities, user preferences)
 * @param {object} [context.platform] - Platform flags (e.g. { supportsDownloadPause: boolean, supportsPopupDefusal: boolean })
 * @param {object} [context.userPermissions] - User-granted consent flags
 * @returns {object} Safe Action Policy Outcome
 */
export function evaluateSafeActionPolicy(verdict, context = {}) {
  // 1. Validate Verdict Contract Input
  const contractValidation = validateVerdictContract(verdict);
  if (!contractValidation.valid) {
    throw new Error(`[SafeActionPolicy] Invalid Verdict Contract: ${contractValidation.errors.join('; ')}`);
  }

  const evaluationId = generatePolicyEvaluationId(verdict.scanId);
  const timestamp = new Date().toISOString();
  const platform = context.platform || {};
  const userPerms = context.userPermissions || {};

  // Extract signals and calibration
  const classification = verdict.riskClassification;
  const isAbstain = classification === 'ABSTAIN';
  const isHighRisk = classification === 'HIGH_RISK';
  const isCaution = classification === 'CAUTION';
  const isSafe = classification === 'SAFE';

  const calibratedConfidence = typeof verdict.calibratedConfidence === 'number'
    ? verdict.calibratedConfidence
    : null;
  const isUncalibrated = calibratedConfidence === null;

  // Check for deterministic hard override evidence
  const evidenceList = Array.isArray(verdict.evidence) ? verdict.evidence : [];
  const hardOverrideIds = [
    'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC',
    'SIG_AITM_REVERSE_PROXY',
    'SIG_BITB_FAKE_WINDOW',
    'SIG_MALICIOUS_DOWNLOAD_EXE',
    'SIG_MALICIOUS_DOWNLOAD_APK',
    'SIG_AD_ROTATOR_POPUNDER',
    'SIG_DIGITAL_ARREST_COERCION',
    'SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT'
  ];

  const hasHardOverride = evidenceList.some(e => {
    const id = typeof e === 'string' ? e : e?.id;
    return id && hardOverrideIds.includes(id);
  });

  // -------------------------------------------------------------
  // INVARIANT 1: PRESERVE EXPLICIT ABSTAIN BEHAVIOR
  // If the detector abstained, missing evidence NEVER triggers
  // automated disruption or false assertions of safety.
  // -------------------------------------------------------------
  if (isAbstain) {
    return {
      policyVersion: POLICY_VERSION,
      evaluationId,
      timestamp,
      scanId: verdict.scanId,
      riskClassification: 'ABSTAIN',
      abstentionReason: verdict.abstentionReason || 'INSUFFICIENT_EVIDENCE',
      
      recommendedAction: {
        id: ACTION_TYPES.MANUAL_VERIFY_OFFLINE,
        label: 'Exercise Caution & Verify Through Official Independent Channels',
        urgency: 'ADVISORY',
        safeNextStep: verdict.recommendedAction?.safeNextStep || 'Do not provide sensitive data. Verify directly with the sender.',
        reason: 'Forensic evidence is missing, incomplete, or ambiguous. Safe action policy enforces non-disruptive caution.'
      },

      // Strictly NULL: Uncertain verdicts cannot trigger automatic side effects
      allowedAutomaticAction: null,
      
      requiredUserConfirmation: null,
      
      confidenceAndUncertainty: {
        riskScore: verdict.riskScore,
        calibratedConfidence: null,
        isUncalibrated: true,
        uncertaintyState: 'UNRESOLVED_EVIDENCE',
        knownLimitations: verdict.uncertainty?.knownLimitations || []
      },

      reassessment: {
        requiresReassessment: true,
        ttlSeconds: 300, // 5 minutes reassessment window
        condition: 'NEW_OBSERVABLE_EVIDENCE_REQUIRED'
      },

      auditEvent: {
        policyVersion: POLICY_VERSION,
        evaluationId,
        scanId: verdict.scanId,
        timestamp,
        decision: 'ABSTAIN_ADVISORY_ONLY',
        automaticActionPermitted: false,
        confirmationRequired: false
      }
    };
  }

  // -------------------------------------------------------------
  // INVARIANT 2: BENIGN / SAFE INTERACTIONS
  // -------------------------------------------------------------
  if (isSafe) {
    return {
      policyVersion: POLICY_VERSION,
      evaluationId,
      timestamp,
      scanId: verdict.scanId,
      riskClassification: 'SAFE',
      abstentionReason: null,

      recommendedAction: {
        id: ACTION_TYPES.ALLOW_NORMAL,
        label: 'Proceed Normally',
        urgency: 'NORMAL',
        safeNextStep: verdict.recommendedAction?.safeNextStep || 'Interaction matches verified safe patterns. Proceed with standard security awareness.',
        reason: 'Empirical indicators verified against legitimate allowlists or zero fraud indicators.'
      },

      allowedAutomaticAction: null,
      requiredUserConfirmation: null,

      confidenceAndUncertainty: {
        riskScore: verdict.riskScore,
        calibratedConfidence: calibratedConfidence ?? 0.95,
        isUncalibrated: isUncalibrated,
        uncertaintyState: 'RESOLVED_SAFE',
        knownLimitations: []
      },

      reassessment: {
        requiresReassessment: false,
        ttlSeconds: 86400 // 24 hour cache
      },

      auditEvent: {
        policyVersion: POLICY_VERSION,
        evaluationId,
        scanId: verdict.scanId,
        timestamp,
        decision: 'ALLOW_NORMAL',
        automaticActionPermitted: false,
        confirmationRequired: false
      }
    };
  }

  // -------------------------------------------------------------
  // INVARIANT 3 & 4: HIGH RISK & CAUTION
  // Bounded protective actions. Only reversible actions allowed automatically.
  // -------------------------------------------------------------
  let recommendedActionId = isHighRisk ? ACTION_TYPES.DISPLAY_SCAM_ACTION_CARD : ACTION_TYPES.EXERCISE_CAUTION;
  let urgency = isHighRisk ? 'CRITICAL' : 'HIGH';
  let allowedAutomaticAction = null;
  let requiredUserConfirmation = null;

  // Check for specific reversible automatic actions
  const isExecutableDownload = evidenceList.some(e => {
    const id = typeof e === 'string' ? e : e?.id;
    return id === 'SIG_MALICIOUS_DOWNLOAD_EXE' || id === 'SIG_MALICIOUS_DOWNLOAD_APK';
  });

  const isRoguePopunder = evidenceList.some(e => {
    const id = typeof e === 'string' ? e : e?.id;
    return id === 'SIG_AD_ROTATOR_POPUNDER';
  });

  // Automation eligibility gate:
  // Requires HIGH_RISK AND (calibrated confidence >= 0.85 OR hard deterministic override)
  const isConfidenceEligibleForAutomation = isHighRisk && (
    (!isUncalibrated && calibratedConfidence >= 0.85) || hasHardOverride
  );

  if (isConfidenceEligibleForAutomation) {
    if (isExecutableDownload && platform.supportsDownloadPause) {
      allowedAutomaticAction = {
        actionType: ACTION_TYPES.PAUSE_AND_PROMPT_DOWNLOAD,
        isReversible: true,
        reversalAction: 'RESUME_DOWNLOAD',
        rationale: 'Disguised or unverified executable download paused to prevent arbitrary code execution.',
        requiredPermission: 'downloads'
      };
      requiredUserConfirmation = {
        prompt: 'An unverified executable download was automatically paused. Do you want to cancel and delete it, or download anyway at your own risk?',
        options: ['Cancel & Delete', 'Download Anyway (Override)']
      };
    } else if (isRoguePopunder && platform.supportsPopupDefusal) {
      allowedAutomaticAction = {
        actionType: ACTION_TYPES.DEFUSE_ROGUE_POPUNDER,
        isReversible: true,
        reversalAction: 'ALLOW_POPUP_WINDOW',
        rationale: 'Unprompted ad-rotator or popunder defused to prevent drive-by redirect traps.',
        requiredPermission: 'tabs'
      };
    }
  }

  // If High Risk indicates Digital Arrest or severe financial compromise, route to Recovery
  if (verdict.threatCategory === 'digital_arrest_extortion' || verdict.threatCategory === 'fake_kyc_account_blocking') {
    recommendedActionId = ACTION_TYPES.RECOMMEND_EMERGENCY_RECOVERY;
    requiredUserConfirmation = {
      prompt: 'If you already approved a payment or provided passwords/Aadhaar details, follow the 1930 emergency mitigation steps.',
      options: ['Open Recovery Guide', 'Dismiss Warning']
    };
  }

  return {
    policyVersion: POLICY_VERSION,
    evaluationId,
    timestamp,
    scanId: verdict.scanId,
    riskClassification: classification,
    threatCategory: verdict.threatCategory,
    abstentionReason: null,

    recommendedAction: {
      id: recommendedActionId,
      label: isHighRisk ? 'Halt Interaction & Review Evidence' : 'Exercise Caution',
      urgency,
      safeNextStep: verdict.recommendedAction?.safeNextStep || 'Halt all transactions and verify independently.',
      emergencyHelpline: verdict.recommendedAction?.emergencyHelpline || '1930'
    },

    allowedAutomaticAction,
    requiredUserConfirmation,

    confidenceAndUncertainty: {
      riskScore: verdict.riskScore,
      calibratedConfidence,
      isUncalibrated,
      hasHardOverride,
      uncertaintyState: isConfidenceEligibleForAutomation ? 'HIGH_CONFIDENCE_THREAT' : 'EVALUATION_NEEDS_CONFIRMATION',
      knownLimitations: verdict.uncertainty?.knownLimitations || []
    },

    reassessment: {
      requiresReassessment: false,
      ttlSeconds: isHighRisk ? 600 : 1800
    },

    auditEvent: {
      policyVersion: POLICY_VERSION,
      evaluationId,
      scanId: verdict.scanId,
      timestamp,
      decision: recommendedActionId,
      automaticActionPermitted: allowedAutomaticAction !== null,
      automaticActionType: allowedAutomaticAction?.actionType || null,
      confirmationRequired: requiredUserConfirmation !== null
    }
  };
}

export default {
  POLICY_VERSION,
  ACTION_TYPES,
  PROHIBITED_AUTOMATIC_ACTIONS,
  evaluateSafeActionPolicy
};
