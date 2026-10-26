import test from 'node:test';
import assert from 'node:assert/strict';

import {
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
} from '../shared/verdict-contract.js';

import { scanText } from '../shared/text-scanner.js';
import { verifyUrlAndMessageOnline } from '../shared/online-scam-verifier.js';

test('Verdict Contract: 1. Schema constants and versioning integrity', () => {
  assert.equal(SCHEMA_VERSION, '2.0.0');
  assert.ok(RULE_PACK_VERSION);
  assert.ok(DETECTOR_ENGINE_VERSION);
  assert.ok(INPUT_MODALITIES.length >= 6);
  assert.ok(THREAT_CATEGORIES.length >= 20);
  assert.ok(RISK_CLASSIFICATIONS.includes('SAFE'));
  assert.ok(RISK_CLASSIFICATIONS.includes('HIGH_RISK'));
  assert.ok(RISK_CLASSIFICATIONS.includes('ABSTAIN'));
  assert.ok(ABSTENTION_REASONS.includes('UNABLE_TO_DETERMINE'));
  assert.ok(ABSTENTION_REASONS.includes('INSUFFICIENT_EVIDENCE'));
  assert.ok(ABSTENTION_REASONS.includes('UNSUPPORTED_INPUT'));
});

test('Verdict Contract: 2. Factory createVerdict produces valid schema object', () => {
  const verdict = createVerdict({
    inputModality: 'url',
    threatCategory: 'phishing_credential_harvesting',
    riskClassification: 'HIGH_RISK',
    riskScore: 95,
    evidence: [
      { id: 'SIG_BITB_FAKE_WINDOW_ATTACK', description: 'Browser-in-the-browser fake login window', source: 'content-script' }
    ],
    humanExplanations: ['Fake Google OAuth window detected on unauthorized domain.'],
    recommendedAction: {
      safeNextStep: 'Do not enter passwords. Close this browser window immediately.',
      recoveryRoute: 'phishing_credential_harvesting',
      emergencyHelpline: '1930'
    },
    privacyDisclosure: {
      localOnly: true,
      externalLookups: [],
      redactionsApplied: []
    }
  });

  const validation = validateVerdictContract(verdict);
  assert.equal(validation.valid, true, `Validation failed: ${validation.errors.join('; ')}`);
  assert.equal(verdict.schemaVersion, '2.0.0');
  assert.ok(verdict.scanId.startsWith('scn_'));
  assert.equal(verdict.riskScore, 95);
  assert.equal(verdict.riskClassification, 'HIGH_RISK');
  assert.equal(verdict.threatCategory, 'phishing_credential_harvesting');
  assert.equal(verdict.legacyCompat.action, 'block');
  assert.equal(verdict.legacyCompat.severity, 'danger');
});

test('Verdict Contract: 3. Abstention verdict handles inconclusive / unsupported input without false safety', () => {
  const abstention = createAbstentionVerdict(
    'message',
    'INSUFFICIENT_EVIDENCE',
    'Message text contains no verifiable domain, link, or financial intent keywords.'
  );

  const validation = validateVerdictContract(abstention);
  assert.equal(validation.valid, true);
  assert.equal(abstention.riskClassification, 'ABSTAIN');
  assert.equal(abstention.abstentionReason, 'INSUFFICIENT_EVIDENCE');
  assert.notEqual(abstention.riskClassification, 'SAFE');
  assert.ok(abstention.uncertainty.hasLimitations);
  assert.ok(abstention.recommendedAction.safeNextStep.includes('Do not submit'));
});

test('Verdict Contract: 4. Schema validator catches missing mandatory fields', () => {
  const badVerdict = {
    schemaVersion: '1.0.0', // wrong version
    riskScore: 150 // out of bounds
  };

  const validation = validateVerdictContract(badVerdict);
  assert.equal(validation.valid, false);
  assert.ok(validation.errors.length >= 4);
});

test('Verdict Contract: 5. Integration with scanText returns valid VerdictContract', () => {
  // Test danger scenario
  const dangerInput = 'Urgent: CBI cyber crime cell notice. A narcotics parcel under your Aadhaar has been intercepted. You are under digital arrest. Connect to video call immediately.';
  const resDanger = scanText(dangerInput);

  assert.ok(resDanger.verdictContract, 'scanText must attach verdictContract');
  const validDanger = validateVerdictContract(resDanger.verdictContract);
  assert.equal(validDanger.valid, true);
  assert.equal(resDanger.verdictContract.threatCategory, 'digital_arrest_extortion');
  assert.equal(resDanger.verdictContract.riskClassification, 'HIGH_RISK');

  // Test empty input abstention scenario
  const emptyRes = scanText('');
  assert.ok(emptyRes.verdictContract);
  assert.equal(emptyRes.verdictContract.riskClassification, 'ABSTAIN');
  assert.equal(emptyRes.verdictContract.abstentionReason, 'UNSUPPORTED_INPUT');
});

test('Verdict Contract: 6. Integration with verifyUrlAndMessageOnline produces compliant schema', async () => {
  const mockFetch = async () => ({ ok: false, status: 503 });
  const result = await verifyUrlAndMessageOnline('https://sbi-kyc-update.invalid/login', {
    fetchImpl: mockFetch,
    budgetMs: 200
  });

  assert.ok(result.verdictContract);
  const validation = validateVerdictContract(result.verdictContract);
  assert.equal(validation.valid, true);
  assert.equal(result.verdictContract.threatCategory, 'fake_kyc_account_blocking');
  assert.equal(result.verdictContract.riskClassification, 'HIGH_RISK');
  assert.ok(result.verdictContract.privacyDisclosure);
});
