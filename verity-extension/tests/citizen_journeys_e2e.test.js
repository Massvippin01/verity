/**
 * tests/citizen_journeys_e2e.test.js — End-to-End Citizen Journey Automated Verification
 *
 * Formally verifies the 5 core citizen safety journeys:
 * A. Digital-arrest impersonation & coercive extortion -> Action Card -> Recovery -> Sanitized Receipt.
 * B. Fake refund and UPI collect lure -> Action Card explanation -> Benign payment control (no false alarms).
 * C. Suspicious URL vs Benign control URL -> Normalization, evidence, explanations, offline resilience.
 * D. Already-compromised user -> 4 distinct incident states (password, OTP, transfer, APK) without secret harvesting.
 * E. Uncertain or degraded analysis -> Malformed/unsupported input, offline degradation, and insufficient evidence abstention.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { scanText } from '../shared/text-scanner.js';
import { verifyUrlAndMessageOnline } from '../shared/online-scam-verifier.js';
import {
  getRecoveryGuide,
  generateEvidenceReceipt,
  sanitizeSecrets,
  OFFICIAL_RECOVERY_REGISTRY,
  INCIDENT_TYPES
} from '../shared/recovery-advisor.js';
import {
  validateVerdictContract,
  createAbstentionVerdict
} from '../shared/verdict-contract.js';

test('Citizen Journey A: Digital-Arrest Impersonation & Coercion Flow', async () => {
  const fictionalThreatMsg =
    'URGENT NOTICE: CBI Officer Rajesh Sharma. A narcotics parcel addressed under your Aadhaar has been intercepted by Mumbai Customs. A non-bailable arrest warrant is issued. Connect to video interrogation immediately on WhatsApp +91-9988776655 to verify your identity or face immediate detention.';

  // 1. Scan detection
  const scanRes = scanText(fictionalThreatMsg);
  assert.equal(scanRes.verdict, 'danger', 'Digital arrest threat must evaluate to danger verdict');
  assert.ok(scanRes.score >= 85, `Score must be >= 85, got ${scanRes.score}`);

  // 2. Evidence validation
  const hasDigitalArrestSig = scanRes.signals.some(
    s => s.id === 'SIG_DIGITAL_ARREST_EXTORTION' || s.id === 'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE'
  );
  assert.ok(hasDigitalArrestSig, 'Must emit digital arrest or psycholinguistic extortion signature');

  // 3. Verdict Contract compliance
  const contract = scanRes.verdictContract;
  assert.ok(contract, 'Verdict contract must be attached');
  assert.equal(contract.riskClassification, 'HIGH_RISK');
  assert.equal(contract.threatCategory, 'digital_arrest_extortion');

  // 4. Safe action guidance verification
  const safeStep = contract.recommendedAction.safeNextStep;
  assert.ok(
    safeStep.toLowerCase().includes('do not approve') || safeStep.toLowerCase().includes('caution') || safeStep.toLowerCase().includes('passwords'),
    'Safe action must advise non-compliance with extortion demands'
  );

  // 5. Recovery Mode flow
  const guide = getRecoveryGuide('EXTORTION_OR_DIGITAL_ARREST', 'en');
  assert.ok(guide.title.toLowerCase().includes('digital arrest') || guide.title.toLowerCase().includes('extortion'));
  assert.ok(
    guide.steps.some(step => step.toLowerCase().includes('disconnect') || step.toLowerCase().includes('block')),
    'Recovery steps must advise immediate disconnection'
  );
  assert.ok(
    guide.steps.some(step => step.includes('1930')),
    'Recovery steps must route to National Cyber Crime Helpline 1930'
  );

  // 6. Sanitized Evidence Receipt export with sensitive PII in input
  const rawInputWithSecrets = `${fictionalThreatMsg} My Aadhaar is 2345 6789 0123, card 4111 1111 1111 1111, OTP 654321.`;
  const receipt = generateEvidenceReceipt({
    scanId: contract.scanId,
    rawInput: rawInputWithSecrets,
    verdict: contract,
    lang: 'en'
  });

  assert.ok(receipt.receiptId.startsWith('REC-'), 'Receipt ID must start with REC-');
  assert.equal(receipt.secretsRedacted, true);
  assert.ok(!receipt.sanitizedSummary.includes('2345 6789 0123'), 'Plaintext Aadhaar must be stripped');
  assert.ok(!receipt.sanitizedSummary.includes('4111 1111 1111 1111'), 'Plaintext Card must be stripped');
  assert.ok(!receipt.sanitizedSummary.includes('654321'), 'Plaintext OTP must be stripped');
  assert.ok(receipt.markdownExport.includes('National Cyber Crime Helpline'), 'Markdown receipt must embed official helpline');
  assert.ok(receipt.jsonExport.includes('XXXX-XXXX-') || receipt.jsonExport.includes('[REDACTED'), 'JSON receipt must embed redacted tokens');
});

test('Citizen Journey B: Fake Refund & UPI Collect Deception vs Benign Control', async () => {
  // 1. Deceptive refund collect lure
  const fakeRefundMsg =
    'Dear Customer, your electricity cashback refund of ₹5,000 has been approved. Scan this QR code and enter your secret 6-digit UPI PIN to receive money into your bank: upi://pay?pa=refund-desk@ybl&pn=RefundDesk&am=5000';

  const scamRes = scanText(fakeRefundMsg);
  assert.equal(scamRes.verdict, 'danger', 'Deceptive refund collect must evaluate to danger');
  assert.ok(scamRes.score >= 85, `Score must be >= 85, got ${scamRes.score}`);

  // 2. Verify signal and non-deceptive explanation (PIN is to SEND, not receive)
  const hasUpiTrap = scamRes.signals.some(
    s => s.id === 'SIG_UPI_QR_COLLECT_TRAP' || s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION' || s.id === 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC'
  );
  assert.ok(hasUpiTrap, 'Must flag UPI collect trap or illegal PIN collection');

  const contract = scamRes.verdictContract;
  assert.equal(contract.threatCategory, 'upi_collect_payment_deception');

  // 3. Benign control: Legitimate payment intent must NOT be labeled malicious
  const benignPaymentIntent = 'upi://pay?pa=merchant@icici&pn=CoffeeShop&am=250';
  const benignRes = scanText(benignPaymentIntent);

  assert.equal(benignRes.verdict, 'safe', 'Legitimate P2M merchant payment must evaluate as safe');
  assert.ok(benignRes.score <= 30, `Score must be <= 30, got ${benignRes.score}`);
  assert.ok(
    !benignRes.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'),
    'Legitimate merchant payment must not trigger collect trap'
  );
});

test('Citizen Journey C: Suspicious URL vs Benign Control & Offline Resilience', async () => {
  // 1. Synthetic suspicious URL (brand spoofing + KYC lure)
  const suspiciousUrl = 'https://sbi-kyc-verification-portal.invalid/update-pan';
  const suspRes = scanText(suspiciousUrl);

  assert.equal(suspRes.verdict, 'danger', 'Spoofed banking URL must evaluate to danger');
  assert.ok(suspRes.score >= 85, `Expected score >= 85, got ${suspRes.score}`);
  assert.ok(
    suspRes.signals.some(s => s.id === 'SIG_KYC_CYBER_FRAUD' || s.id === 'RULE_BRAND_NAME_WRONG_DOMAIN'),
    'Must flag KYC cyber fraud or wrong domain'
  );

  // 2. Benign control URL (Official SBI portal on apex .sbi TLD)
  const benignUrl = 'https://retail.onlinesbi.sbi/retail/login.htm';
  const benignRes = scanText(benignUrl);

  assert.equal(benignRes.verdict, 'safe', 'Official bank domain must evaluate as safe');
  assert.ok(benignRes.score <= 20, `Official portal score must be <= 20, got ${benignRes.score}`);
  assert.equal(benignRes.verdictContract.riskClassification, 'SAFE');
  assert.equal(benignRes.verdictContract.threatCategory, 'benign_legitimate_interaction');

  // 3. Offline degradation resilience: verifyUrlAndMessageOnline with network abort
  const offlineMockFetch = () => Promise.reject(new Error('Network is unreachable (air-gapped)'));
  const offlineRes = await verifyUrlAndMessageOnline(suspiciousUrl, {
    fetchImpl: offlineMockFetch,
    budgetMs: 100
  });

  assert.equal(offlineRes.isOfflineFallback, true, 'Must gracefully flag isOfflineFallback');
  assert.equal(offlineRes.severity, 'danger', 'Offline heuristics must still catch the suspicious URL');
  assert.ok(offlineRes.onlineProofSteps.every(step => step.status === 'skipped' || step.status === 'failed' || step.status === 'passed'));
});

test('Citizen Journey D: Already-Compromised User Across 4 Distinct States', () => {
  const incidentStates = [
    {
      state: 'ENTERED_PASSWORD',
      keyPhrases: ['password', '2fa', 'sessions']
    },
    {
      state: 'SHARED_OTP_OR_PIN',
      keyPhrases: ['1930', 'freeze', 'pin']
    },
    {
      state: 'APPROVED_PAYMENT_OR_TRANSFERRED',
      keyPhrases: ['1930', 'golden hour', 'freeze']
    },
    {
      state: 'INSTALLED_SUSPICIOUS_APP',
      keyPhrases: ['airplane', 'safe mode', 'uninstall']
    }
  ];

  for (const item of incidentStates) {
    const guide = getRecoveryGuide(item.state, 'en');
    assert.ok(guide.steps.length >= 3, `State ${item.state} must provide at least 3 actionable steps`);

    const combinedText = guide.steps.join(' ').toLowerCase();
    for (const phrase of item.keyPhrases) {
      assert.ok(
        combinedText.includes(phrase),
        `State ${item.state} steps must mention "${phrase}"`
      );
    }

    // Invariant: VERITY must never ask the user to type their real secret credentials
    assert.ok(!combinedText.includes('enter your otp here'), 'Must never solicit real OTP');
    assert.ok(!combinedText.includes('enter your password here'), 'Must never solicit real password');
    assert.ok(!combinedText.includes('enter your credit card number'), 'Must never solicit card numbers');
    assert.ok(!combinedText.includes('enter your upi pin here'), 'Must never solicit real UPI PIN');
  }
});

test('Citizen Journey E: Uncertain or Degraded Analysis & Explicit Abstention', async () => {
  // 1. Malformed / Unsupported input
  const nullRes = scanText(null);
  assert.equal(nullRes.verdictContract.riskClassification, 'ABSTAIN');
  assert.equal(nullRes.verdictContract.abstentionReason, 'UNSUPPORTED_INPUT');

  const emptyRes = scanText('   ');
  assert.equal(emptyRes.verdictContract.riskClassification, 'ABSTAIN');
  assert.equal(emptyRes.verdictContract.abstentionReason, 'UNSUPPORTED_INPUT');

  // 2. Insufficient evidence input (short ambiguous text without indicators or links)
  const ambiguousText = 'hello please call me';
  const ambiguousRes = scanText(ambiguousText);
  assert.equal(
    ambiguousRes.verdictContract.riskClassification,
    'ABSTAIN',
    'Ambiguous text with zero verifiable indicators must yield ABSTAIN contract'
  );
  assert.equal(
    ambiguousRes.verdictContract.abstentionReason,
    'INSUFFICIENT_EVIDENCE',
    'Abstention reason must be INSUFFICIENT_EVIDENCE'
  );
  assert.equal(
    ambiguousRes.verdictContract.threatCategory,
    'unsupported_or_unknown',
    'Threat category must be unsupported_or_unknown'
  );

  // 3. Contract validation on abstention verdict
  const validation = validateVerdictContract(ambiguousRes.verdictContract);
  assert.equal(validation.valid, true, 'Abstention verdict must strictly pass contract validation');
});
