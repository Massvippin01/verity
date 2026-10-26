/**
 * tests/safe_action_policy.test.js — Unit Tests for Bounded Safe Action Engine
 *
 * Verifies all deterministic policy invariants, explicit ABSTAIN preservation,
 * confidence calibration gates, prohibited automatic actions, and audit logging.
 */

import test from 'node:test';
import assert from 'node:assert';

import {
  POLICY_VERSION,
  ACTION_TYPES,
  PROHIBITED_AUTOMATIC_ACTIONS,
  evaluateSafeActionPolicy
} from '../shared/safe-action-policy.js';

import {
  createVerdict,
  createAbstentionVerdict
} from '../shared/verdict-contract.js';

test('Safe Action Policy: Invariant 1 — Explicit ABSTAIN never triggers automatic disruption', () => {
  const abstainVerdict = createAbstentionVerdict(
    'message',
    'INSUFFICIENT_EVIDENCE',
    'Short vague text cannot be definitively evaluated.'
  );

  const policy = evaluateSafeActionPolicy(abstainVerdict, {
    platform: { supportsDownloadPause: true, supportsPopupDefusal: true }
  });

  assert.strictEqual(policy.policyVersion, POLICY_VERSION);
  assert.strictEqual(policy.riskClassification, 'ABSTAIN');
  assert.strictEqual(policy.recommendedAction.id, ACTION_TYPES.MANUAL_VERIFY_OFFLINE);
  assert.strictEqual(policy.allowedAutomaticAction, null, 'ABSTAIN must NEVER authorize automatic action');
  assert.strictEqual(policy.confidenceAndUncertainty.uncertaintyState, 'UNRESOLVED_EVIDENCE');
  assert.strictEqual(policy.auditEvent.automaticActionPermitted, false);
});

test('Safe Action Policy: Invariant 2 — Benign SAFE verdicts allow normal proceeding without side-effects', () => {
  const safeVerdict = createVerdict({
    inputModality: 'payment_intent',
    threatCategory: 'benign_legitimate_interaction',
    riskClassification: 'SAFE',
    riskScore: 0,
    calibratedConfidence: 0.98,
    evidence: [{ id: 'VALID_NPCI_MERCHANT_VPA', description: 'Verified official merchant handle', source: 'allowlist' }],
    recommendedAction: { safeNextStep: 'Proceed with normal awareness.' }
  });

  const policy = evaluateSafeActionPolicy(safeVerdict);

  assert.strictEqual(policy.riskClassification, 'SAFE');
  assert.strictEqual(policy.recommendedAction.id, ACTION_TYPES.ALLOW_NORMAL);
  assert.strictEqual(policy.allowedAutomaticAction, null);
  assert.strictEqual(policy.requiredUserConfirmation, null);
  assert.strictEqual(policy.confidenceAndUncertainty.uncertaintyState, 'RESOLVED_SAFE');
});

test('Safe Action Policy: Invariant 3 — Uncalibrated models cannot independently authorize automatic actions', () => {
  const uncalibratedVerdict = createVerdict({
    inputModality: 'url',
    threatCategory: 'brand_impersonation',
    riskClassification: 'HIGH_RISK',
    riskScore: 88,
    calibratedConfidence: null, // Model output is uncalibrated!
    evidence: [{ id: 'GENERIC_HEURISTIC_HIT', description: 'Lexical entropy threshold reached', source: 'uncalibrated_heuristics' }],
    recommendedAction: { safeNextStep: 'Do not submit credentials.' }
  });

  const policy = evaluateSafeActionPolicy(uncalibratedVerdict, {
    platform: { supportsDownloadPause: true, supportsPopupDefusal: true }
  });

  assert.strictEqual(policy.riskClassification, 'HIGH_RISK');
  assert.strictEqual(policy.allowedAutomaticAction, null, 'Uncalibrated high-risk signals cannot trigger automatic actions');
  assert.strictEqual(policy.confidenceAndUncertainty.isUncalibrated, true);
  assert.strictEqual(policy.confidenceAndUncertainty.uncertaintyState, 'EVALUATION_NEEDS_CONFIRMATION');
});

test('Safe Action Policy: Invariant 4 — Bounded reversible protective actions authorized for verified threats', () => {
  const downloadThreatVerdict = createVerdict({
    inputModality: 'file_download',
    threatCategory: 'malicious_application_dropper',
    riskClassification: 'HIGH_RISK',
    riskScore: 95,
    calibratedConfidence: 0.92,
    evidence: [
      { id: 'SIG_MALICIOUS_DOWNLOAD_EXE', description: 'Masquerading double extension .mp4.exe', source: 'file_magic' }
    ],
    recommendedAction: { safeNextStep: 'Do not execute downloaded file.' }
  });

  const policy = evaluateSafeActionPolicy(downloadThreatVerdict, {
    platform: { supportsDownloadPause: true }
  });

  assert.strictEqual(policy.riskClassification, 'HIGH_RISK');
  assert.ok(policy.allowedAutomaticAction !== null, 'Reversible download pause is permitted');
  assert.strictEqual(policy.allowedAutomaticAction.actionType, ACTION_TYPES.PAUSE_AND_PROMPT_DOWNLOAD);
  assert.strictEqual(policy.allowedAutomaticAction.isReversible, true);
  assert.strictEqual(policy.allowedAutomaticAction.reversalAction, 'RESUME_DOWNLOAD');
  assert.ok(policy.requiredUserConfirmation !== null, 'User confirmation must be prompted');
  assert.strictEqual(policy.auditEvent.automaticActionPermitted, true);
});

test('Safe Action Policy: Invariant 5 — Severe extortion routes to Emergency Recovery with confirmation', () => {
  const digitalArrestVerdict = createVerdict({
    inputModality: 'message',
    threatCategory: 'digital_arrest_extortion',
    riskClassification: 'HIGH_RISK',
    riskScore: 90,
    calibratedConfidence: 0.95,
    evidence: [
      { id: 'SIG_DIGITAL_ARREST_COERCION', description: 'Impersonation of law enforcement demanding immediate WhatsApp video interrogation', source: 'nlp' }
    ],
    recommendedAction: {
      safeNextStep: 'Disconnect immediately. Police in India NEVER interrogate over video calls.',
      emergencyHelpline: '1930'
    }
  });

  const policy = evaluateSafeActionPolicy(digitalArrestVerdict);

  assert.strictEqual(policy.recommendedAction.id, ACTION_TYPES.RECOMMEND_EMERGENCY_RECOVERY);
  assert.strictEqual(policy.recommendedAction.emergencyHelpline, '1930');
  assert.ok(policy.requiredUserConfirmation !== null);
  assert.ok(policy.requiredUserConfirmation.options.includes('Open Recovery Guide'));
});

test('Safe Action Policy: Invariant 6 — Irreversible actions are PROHIBITED from automated execution', () => {
  for (const prohibited of PROHIBITED_AUTOMATIC_ACTIONS) {
    assert.strictEqual(
      Object.values(ACTION_TYPES).includes(prohibited),
      false,
      `Prohibited action "${prohibited}" must NEVER be an ACTION_TYPE`
    );
  }
});

test('Safe Action Policy: Invariant 7 — Emits structured audit event for local flight recorder', () => {
  const verdict = createVerdict({
    inputModality: 'composite',
    threatCategory: 'phishing_credential_harvesting',
    riskClassification: 'HIGH_RISK',
    riskScore: 85,
    recommendedAction: { safeNextStep: 'Halt interaction.' }
  });

  const policy = evaluateSafeActionPolicy(verdict);

  assert.ok(policy.auditEvent, 'Audit event must be present');
  assert.strictEqual(policy.auditEvent.policyVersion, POLICY_VERSION);
  assert.strictEqual(policy.auditEvent.scanId, verdict.scanId);
  assert.ok(policy.auditEvent.evaluationId.startsWith('pol_'));
  assert.ok(policy.auditEvent.timestamp);
});
