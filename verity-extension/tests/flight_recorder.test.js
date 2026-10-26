/**
 * tests/flight_recorder.test.js — Privacy-First Incident Flight Recorder Tests
 *
 * Verifies fact vs assertion separation, Aadhaar/PAN/OTP secret sanitization,
 * ring buffer capacity limits, user interaction logging, tamper checksums, and export controls.
 */

import test from 'node:test';
import assert from 'node:assert';

import {
  FlightRecorder,
  DEFAULT_MAX_CAPACITY,
  LEGAL_DISCLAIMER,
  sanitizeFlightRecorderSecrets,
  computeRecordChecksum
} from '../shared/flight-recorder.js';

import { createVerdict } from '../shared/verdict-contract.js';

test('Flight Recorder: Fact vs Assertion separation & Default no-raw-message storage', () => {
  const recorder = new FlightRecorder({ maxCapacity: 5 });

  const verdict = createVerdict({
    inputModality: 'message',
    threatCategory: 'digital_arrest_extortion',
    riskClassification: 'HIGH_RISK',
    riskScore: 90,
    evidence: [{ id: 'SIG_COERCION', description: 'CBI impersonation with arrest warrant threat', source: 'nlp' }],
    recommendedAction: { safeNextStep: 'Do not transfer funds.' }
  });

  const record = recorder.recordIncident({
    verdict,
    policyOutcome: {
      policyVersion: '1.0.0',
      recommendedAction: { id: 'RECOMMEND_EMERGENCY_RECOVERY' }
    },
    userAssertions: {
      reportedSender: 'WhatsApp caller claiming to be CBI Officer Rajesh',
      claimedLoss: '₹50,000 demanded'
    },
    observedFacts: ['Origin protocol: WhatsApp VoIP', 'Regex match: PMLA Section 45'],
    rawSnippet: 'URGENT: CBI Officer demand transfer to RBI safe account.',
    storeSnippet: false // Default: do not store raw snippet
  });

  assert.ok(record.recordId.startsWith('rec_'));
  assert.strictEqual(record.sanitizedSnippet, null, 'Raw snippet must NOT be stored when storeSnippet is false');
  assert.deepStrictEqual(record.userAssertions, {
    reportedSender: 'WhatsApp caller claiming to be CBI Officer Rajesh',
    claimedLoss: '₹50,000 demanded'
  });
  assert.ok(record.observedFacts.includes('Origin protocol: WhatsApp VoIP'));
  assert.ok(record.observedFacts.includes('CBI impersonation with arrest warrant threat'));
  assert.ok(record.checksum, 'SHA-256 integrity checksum must be computed');
});

test('Flight Recorder: Secret Sanitizer masks Aadhaar, PAN, Card, OTP, CVV, Phone, and Password', () => {
  const sensitiveText = 
    'Aadhaar: 2345 6789 0123. PAN: ABCDE1234F. Card: 4111 2222 3333 4444. ' +
    'CVV: 789. OTP: 456123. Password: SuperSecret123. Phone: +91 9876543210.';

  const sanitized = sanitizeFlightRecorderSecrets(sensitiveText);

  assert.ok(sanitized.includes('XXXX-XXXX-0123'), 'Aadhaar must be masked');
  assert.ok(sanitized.includes('ABCDE****F'), 'PAN must be masked');
  assert.ok(sanitized.includes('****-****-****-4444'), 'Card must be masked');
  assert.ok(sanitized.includes('[REDACTED_CVV]'), 'CVV must be redacted');
  assert.ok(sanitized.includes('[REDACTED_PIN]'), 'OTP must be redacted');
  assert.ok(sanitized.includes('[REDACTED_PASSWORD]'), 'Password must be redacted');
  assert.ok(sanitized.includes('+91-XXXXX-XX210'), 'Phone number must be masked');
  assert.strictEqual(sanitized.includes('SuperSecret123'), false, 'Cleartext password must not appear');
});

test('Flight Recorder: Ring Buffer capacity prunes oldest records', () => {
  const recorder = new FlightRecorder({ maxCapacity: 3 });

  for (let i = 1; i <= 5; i++) {
    const verdict = createVerdict({
      scanId: `scn_test_${i}`,
      threatCategory: 'phishing_credential_harvesting',
      riskClassification: 'HIGH_RISK',
      riskScore: 70 + i,
      recommendedAction: { safeNextStep: `Step ${i}` }
    });
    recorder.recordIncident({ verdict });
  }

  const timeline = recorder.getTimeline();
  assert.strictEqual(timeline.length, 3, 'Timeline must not exceed maxCapacity (3)');
  // Oldest (1 and 2) must have been pruned; 3, 4, 5 must remain
  assert.strictEqual(timeline[0].scanId, 'scn_test_3');
  assert.strictEqual(timeline[1].scanId, 'scn_test_4');
  assert.strictEqual(timeline[2].scanId, 'scn_test_5');
});

test('Flight Recorder: User interaction logging and recovery progress tracking', () => {
  const recorder = new FlightRecorder({ maxCapacity: 10 });
  const verdict = createVerdict({
    threatCategory: 'digital_arrest_extortion',
    riskClassification: 'HIGH_RISK',
    riskScore: 90,
    recommendedAction: { safeNextStep: 'Dial 1930.' }
  });

  const record = recorder.recordIncident({ verdict });
  const initialChecksum = record.checksum;

  recorder.logUserInteraction(record.recordId, {
    action: 'EMERGENCY_CALL_INITIATED',
    stepId: 'CALL_1930',
    note: 'Citizen dialed National Cyber Crime helpline 1930'
  });

  recorder.logUserInteraction(record.recordId, {
    action: 'RECOVERY_STEP_DONE',
    stepId: 'DISCONNECT_CALL',
    note: 'WhatsApp call terminated'
  });

  const updated = recorder.getTimeline()[0];
  assert.strictEqual(updated.userInteractions.length, 2);
  assert.deepStrictEqual(updated.recoveryProgress, ['CALL_1930', 'DISCONNECT_CALL']);
  assert.notStrictEqual(updated.checksum, initialChecksum, 'Checksum must update after interactions');
  assert.strictEqual(updated.checksum, computeRecordChecksum(updated), 'Checksum must match recomputed record state');
});

test('Flight Recorder: Single incident deletion and complete purge', () => {
  const recorder = new FlightRecorder({ maxCapacity: 10 });

  const r1 = recorder.recordIncident({
    verdict: createVerdict({ scanId: 'scn_1', threatCategory: 'phishing_credential_harvesting', riskClassification: 'HIGH_RISK', riskScore: 80, recommendedAction: { safeNextStep: 'Halt' } })
  });
  const r2 = recorder.recordIncident({
    verdict: createVerdict({ scanId: 'scn_2', threatCategory: 'fake_refund_cashback_reward', riskClassification: 'HIGH_RISK', riskScore: 85, recommendedAction: { safeNextStep: 'Halt' } })
  });

  assert.strictEqual(recorder.getTimeline().length, 2);

  const deleted = recorder.deleteRecord(r1.recordId);
  assert.strictEqual(deleted, true);
  assert.strictEqual(recorder.getTimeline().length, 1);
  assert.strictEqual(recorder.getTimeline()[0].recordId, r2.recordId);

  recorder.purgeAll();
  assert.strictEqual(recorder.getTimeline().length, 0);
});

test('Flight Recorder: Markdown and JSON exports include Legal Disclaimer', () => {
  const recorder = new FlightRecorder({ maxCapacity: 10 });

  recorder.recordIncident({
    verdict: createVerdict({
      threatCategory: 'digital_arrest_extortion',
      riskClassification: 'HIGH_RISK',
      riskScore: 92,
      recommendedAction: { safeNextStep: 'Call 1930' }
    }),
    policyOutcome: {
      policyVersion: '1.0.0',
      recommendedAction: { id: 'RECOMMEND_EMERGENCY_RECOVERY' }
    },
    userAssertions: { suspectPhone: '+91-9988776655' }
  });

  const jsonExport = recorder.exportTimelineJson();
  const parsed = JSON.parse(jsonExport);
  assert.strictEqual(parsed.recordCount, 1);
  assert.strictEqual(parsed.disclaimer, LEGAL_DISCLAIMER);

  const mdExport = recorder.exportTimelineMarkdown();
  assert.ok(mdExport.includes(LEGAL_DISCLAIMER), 'Markdown export must contain legal disclaimer');
  assert.ok(mdExport.includes('DIGITAL_ARREST_EXTORTION'));
  assert.ok(mdExport.includes('+91-XXXXX-XX655'), 'Suspect phone in assertions must be masked');
});
