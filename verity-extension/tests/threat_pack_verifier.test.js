/**
 * tests/threat_pack_verifier.test.js — Cryptographic Threat-Pack Verification Tests
 *
 * Verifies standard Ed25519 digital signature validation, anti-rollback protection,
 * expiration handling, key revocation, clock-skew guards, and malformed bundle rejection.
 */

import test from 'node:test';
import assert from 'node:assert';

import {
  THREAT_PACK_SCHEMA_VERSION,
  verifyThreatPack,
  generateTestEd25519KeyPair,
  signThreatPackForTest,
  normalizeIndicatorValue
} from '../shared/threat-pack-verifier.js';

// Setup local test key infrastructure
const keyPair1 = generateTestEd25519KeyPair();
const keyPair2 = generateTestEd25519KeyPair();

const trustedKeystore = new Map([
  [
    'key-ed25519-v1',
    {
      publicKeyPem: keyPair1.publicKeyPem,
      issuer: 'verity-threat-intel-authority',
      status: 'active'
    }
  ],
  [
    'key-ed25519-revoked',
    {
      publicKeyPem: keyPair2.publicKeyPem,
      issuer: 'verity-threat-intel-authority',
      status: 'revoked'
    }
  ]
]);

function createBaseTestPack(sequence = 10, expiresOffsetMs = 86400000) {
  const now = Date.now();
  return {
    schemaVersion: THREAT_PACK_SCHEMA_VERSION,
    packId: 'bharat-threat-pack-test-2026',
    sequence,
    issuer: 'verity-threat-intel-authority',
    keyId: 'key-ed25519-v1',
    createdAt: new Date(now - 1000).toISOString(),
    expiresAt: new Date(now + expiresOffsetMs).toISOString(),
    indicators: [
      {
        type: 'domain',
        value: 'sbi-kyc-fraud-login.invalid',
        threatCategory: 'fake_kyc_account_blocking',
        severity: 'HIGH_RISK',
        confidence: 0.99,
        provenance: 'I4C-advisory',
        action: 'block'
      },
      {
        type: 'vpa',
        value: 'ELECTRICITY-BILL-REFUND@YBL',
        threatCategory: 'upi_collect_payment_deception',
        severity: 'HIGH_RISK',
        confidence: 0.95,
        provenance: 'NPCI-alert',
        action: 'block'
      }
    ],
    revocations: []
  };
}

test('Threat Pack Verifier: Case 1 — Valid Ed25519 signature passes verification & normalizes indicators', () => {
  const unsigned = createBaseTestPack(15);
  const signed = signThreatPackForTest(unsigned, keyPair1.privateKeyPem);

  const result = verifyThreatPack(signed, {
    trustedKeys: trustedKeystore,
    currentSequence: 10
  });

  assert.strictEqual(result.verified, true);
  assert.strictEqual(result.verifiedPack.packId, 'bharat-threat-pack-test-2026');
  assert.strictEqual(result.verifiedPack.sequence, 15);
  // Verify indicators were normalized (e.g. lowercase VPA)
  assert.strictEqual(result.verifiedPack.indicators[1].value, 'electricity-bill-refund@ybl');
});

test('Threat Pack Verifier: Case 2 — Tampered indicator payload fails with INVALID_SIGNATURE', () => {
  const unsigned = createBaseTestPack(15);
  const signed = signThreatPackForTest(unsigned, keyPair1.privateKeyPem);

  // Adversary tampers with an indicator value after signing
  signed.indicators[0].value = 'attacker-tampered-domain.invalid';

  const result = verifyThreatPack(signed, {
    trustedKeys: trustedKeystore,
    currentSequence: 10
  });

  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.errorCode, 'INVALID_SIGNATURE');
});

test('Threat Pack Verifier: Case 3 — Corrupted signature fails validation', () => {
  const unsigned = createBaseTestPack(15);
  const signed = signThreatPackForTest(unsigned, keyPair1.privateKeyPem);

  // Corrupt signature hex string
  signed.signature = 'deadbeef' + signed.signature.slice(8);

  const result = verifyThreatPack(signed, {
    trustedKeys: trustedKeystore,
    currentSequence: 10
  });

  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.errorCode, 'INVALID_SIGNATURE');
});

test('Threat Pack Verifier: Case 4 — Sequence rollback / replay attack fails with SEQUENCE_ROLLBACK_DETECTED', () => {
  // Current active sequence is 20, but incoming pack has sequence 18
  const unsigned = createBaseTestPack(18);
  const signed = signThreatPackForTest(unsigned, keyPair1.privateKeyPem);

  const result = verifyThreatPack(signed, {
    trustedKeys: trustedKeystore,
    currentSequence: 20
  });

  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.errorCode, 'SEQUENCE_ROLLBACK_DETECTED');
});

test('Threat Pack Verifier: Case 5 — Expired threat pack fails with PACK_EXPIRED', () => {
  // Pack expired 1 hour ago
  const unsigned = createBaseTestPack(15, -3600000);
  const signed = signThreatPackForTest(unsigned, keyPair1.privateKeyPem);

  const result = verifyThreatPack(signed, {
    trustedKeys: trustedKeystore,
    currentSequence: 10
  });

  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.errorCode, 'PACK_EXPIRED');
});

test('Threat Pack Verifier: Case 6 — Future timestamp beyond acceptable clock skew fails with FUTURE_TIMESTAMP_DETECTED', () => {
  const unsigned = createBaseTestPack(15);
  // Created 1 hour in the future
  unsigned.createdAt = new Date(Date.now() + 3600000).toISOString();
  const signed = signThreatPackForTest(unsigned, keyPair1.privateKeyPem);

  const result = verifyThreatPack(signed, {
    trustedKeys: trustedKeystore,
    currentSequence: 10
  });

  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.errorCode, 'FUTURE_TIMESTAMP_DETECTED');
});

test('Threat Pack Verifier: Case 7 — Revoked signing key fails with SIGNING_KEY_REVOKED', () => {
  const unsigned = createBaseTestPack(15);
  unsigned.keyId = 'key-ed25519-revoked';
  const signed = signThreatPackForTest(unsigned, keyPair2.privateKeyPem);

  const result = verifyThreatPack(signed, {
    trustedKeys: trustedKeystore,
    currentSequence: 10
  });

  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.errorCode, 'SIGNING_KEY_REVOKED');
});

test('Threat Pack Verifier: Case 8 — Untrusted key ID fails with UNTRUSTED_KEY_ID', () => {
  const unsigned = createBaseTestPack(15);
  unsigned.keyId = 'key-unknown-rogue';
  const signed = signThreatPackForTest(unsigned, keyPair1.privateKeyPem);

  const result = verifyThreatPack(signed, {
    trustedKeys: trustedKeystore,
    currentSequence: 10
  });

  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.errorCode, 'UNTRUSTED_KEY_ID');
});

test('Threat Pack Verifier: Case 9 — Issuer mismatch fails with ISSUER_MISMATCH', () => {
  const unsigned = createBaseTestPack(15);
  unsigned.issuer = 'rogue-impersonated-issuer';
  const signed = signThreatPackForTest(unsigned, keyPair1.privateKeyPem);

  const result = verifyThreatPack(signed, {
    trustedKeys: trustedKeystore,
    currentSequence: 10
  });

  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.errorCode, 'ISSUER_MISMATCH');
});

test('Threat Pack Verifier: Case 10 — Malformed schema is rejected with MALFORMED_SCHEMA', () => {
  const malformed = {
    schemaVersion: '0.1.0',
    packId: 12345 // Bad type
  };

  const result = verifyThreatPack(malformed, {
    trustedKeys: trustedKeystore,
    currentSequence: 0
  });

  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.errorCode, 'MALFORMED_SCHEMA');
});
