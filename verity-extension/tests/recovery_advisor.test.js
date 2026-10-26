import test from 'node:test';
import assert from 'node:assert/strict';

import {
  OFFICIAL_RECOVERY_REGISTRY,
  INCIDENT_TYPES,
  RECOVERY_GUIDES,
  sanitizeSecrets,
  generateEvidenceReceipt,
  getRecoveryGuide
} from '../shared/recovery-advisor.js';

test('Recovery Advisor: 1. Official emergency registry completeness', () => {
  assert.equal(OFFICIAL_RECOVERY_REGISTRY.helpline.number, '1930');
  assert.ok(OFFICIAL_RECOVERY_REGISTRY.helpline.title.includes('CFCFRMS'));
  assert.equal(OFFICIAL_RECOVERY_REGISTRY.portal.url, 'https://cybercrime.gov.in');
  assert.ok(OFFICIAL_RECOVERY_REGISTRY.aadhaarLock.url.includes('myaadhaar.uidai.gov.in'));
  assert.ok(OFFICIAL_RECOVERY_REGISTRY.bankHelplines.length >= 6);
  
  // Verify all 6 major Indian banks have emergency contact info
  const sbi = OFFICIAL_RECOVERY_REGISTRY.bankHelplines.find(b => b.bank.includes('SBI'));
  assert.ok(sbi && sbi.phone);
});

test('Recovery Advisor: 2. Complete decision tree across all 10 citizen action states', () => {
  assert.equal(INCIDENT_TYPES.length, 10);

  for (const type of INCIDENT_TYPES) {
    const guide = getRecoveryGuide(type, 'en');
    assert.ok(guide.title, `Missing title for ${type}`);
    assert.ok(Array.isArray(guide.steps) && guide.steps.length >= 3, `Insufficient steps for ${type}`);
    assert.ok(guide.urgency, `Missing urgency for ${type}`);
    assert.ok(guide.primaryHelpline.number === '1930');
  }
});

test('Recovery Advisor: 3. Multilingual recovery guidance (English, Tamil, Hindi, Telugu)', () => {
  const incident = 'APPROVED_PAYMENT_OR_TRANSFERRED';

  const enGuide = getRecoveryGuide(incident, 'en');
  const taGuide = getRecoveryGuide(incident, 'ta');
  const hiGuide = getRecoveryGuide(incident, 'hi');
  const teGuide = getRecoveryGuide(incident, 'te');

  assert.ok(enGuide.steps[0].includes('GOLDEN HOUR'));
  assert.ok(taGuide.steps[0].includes('பொன் நேரம்'));
  assert.ok(hiGuide.steps[0].includes('गोल्डन ऑवर'));
  assert.ok(teGuide.steps[0].includes('గోల్డెన్ అవర్'));
});

test('Recovery Advisor: 4. Automatic secret redaction prevents credential leakage', () => {
  // Test PAN / Credit Card 16-digit redaction
  const rawCard = 'Victim paid using card 4111 2222 3333 4567 on payment portal';
  const sanitizedCard = sanitizeSecrets(rawCard);
  assert.ok(!sanitizedCard.includes('4111'), 'Card PAN must be masked');
  assert.ok(sanitizedCard.includes('****-****-****-4567'), 'Last 4 digits should remain for police identification');

  // Test Indian Aadhaar 12-digit redaction
  const rawAadhaar = 'Aadhaar submitted: 5432 1098 7654';
  const sanitizedAadhaar = sanitizeSecrets(rawAadhaar);
  assert.ok(!sanitizedAadhaar.includes('5432'), 'Aadhaar must be masked');
  assert.ok(sanitizedAadhaar.includes('XXXX-XXXX-7654'));

  // Test OTP, PIN, and CVV redaction
  const rawSecrets = 'OTP: 892143 and cvv: 921 and password: SecretMasterKey99!';
  const sanitizedSecrets = sanitizeSecrets(rawSecrets);
  assert.ok(!sanitizedSecrets.includes('892143'), 'OTP must be redacted');
  assert.ok(!sanitizedSecrets.includes('921'), 'CVV must be redacted');
  assert.ok(!sanitizedSecrets.includes('SecretMasterKey99!'), 'Password must be redacted');
  assert.ok(sanitizedSecrets.includes('[REDACTED_PIN]'));
  assert.ok(sanitizedSecrets.includes('[REDACTED_CVV]'));
  assert.ok(sanitizedSecrets.includes('[REDACTED_PASSWORD]'));
});

test('Recovery Advisor: 5. Evidence receipt generation produces formatted sanitized exports', () => {
  const receipt = generateEvidenceReceipt({
    scanId: 'scn_test123',
    rawInput: 'Phishing trap on https://fake-sbi.invalid/login with Card 4111222233338888 and OTP 654321',
    verdict: {
      scanId: 'scn_test123',
      riskClassification: 'HIGH_RISK',
      score: 95,
      evidence: [
        { id: 'SIG_KYC_CYBER_FRAUD', description: 'Fake bank KYC credential trap' }
      ]
    },
    lang: 'en'
  });

  assert.ok(receipt.receiptId.startsWith('REC-'));
  assert.ok(receipt.sanitizedSummary.includes('****-****-****-8888'));
  assert.ok(!receipt.sanitizedSummary.includes('654321'));
  assert.ok(receipt.markdownExport.includes('**National Cyber Crime Helpline**: Call **1930**'));
  assert.ok(receipt.jsonExport.includes('REC-'));
});
