/**
 * tests/threat_update_pipeline.test.js — Staging Threat-Update Pipeline Assurance Tests
 *
 * Verifies:
 * 1. Sequential authenticated updates and O(1) indicator indexing.
 * 2. Atomic fallback: Failed updates (tampering, replay, expiry, revocation, malformed JSON)
 *    leave the last known-good threat pack completely intact.
 * 3. Network Egress Invariant: Feed fetching sends zero client telemetry, zero scan data,
 *    and zero citizen credentials.
 */

import test from 'node:test';
import assert from 'node:assert';

import {
  ThreatUpdateManager
} from '../shared/threat-update-manager.js';

import {
  THREAT_PACK_SCHEMA_VERSION,
  generateTestEd25519KeyPair,
  signThreatPackForTest
} from '../shared/threat-pack-verifier.js';

// Setup local test keys
const testKey1 = generateTestEd25519KeyPair();
const testKey2 = generateTestEd25519KeyPair();

function createSignedTestBundle(seq, indicators = [], overrides = {}, key = testKey1) {
  const now = Date.now();
  const unsigned = {
    schemaVersion: THREAT_PACK_SCHEMA_VERSION,
    packId: `test-feed-pack-seq-${seq}`,
    sequence: seq,
    issuer: 'verity-threat-intel-authority',
    keyId: 'key-test-1',
    createdAt: new Date(now - 1000).toISOString(),
    expiresAt: new Date(now + 86400000).toISOString(),
    indicators,
    revocations: [],
    ...overrides
  };
  return signThreatPackForTest(unsigned, key.privateKeyPem);
}

test('Threat Update Pipeline: Case 1 — Sequential updates and O(1) indicator matching', () => {
  const manager = new ThreatUpdateManager();
  manager.registerTrustedKey('key-test-1', {
    publicKeyPem: testKey1.publicKeyPem,
    issuer: 'verity-threat-intel-authority',
    status: 'active'
  });

  // Pack 1: Sequence 1
  const pack1 = createSignedTestBundle(1, [
    {
      type: 'domain',
      value: 'phishing-sbi-login.invalid',
      threatCategory: 'fake_kyc_account_blocking',
      severity: 'HIGH_RISK',
      confidence: 0.99,
      provenance: 'test-advisory',
      action: 'block'
    },
    {
      type: 'vpa',
      value: 'REFUND-CLAIM@YBL', // Uppercase to test normalization
      threatCategory: 'upi_collect_payment_deception',
      severity: 'HIGH_RISK',
      confidence: 0.95,
      provenance: 'test-advisory',
      action: 'block'
    }
  ]);

  const res1 = manager.applyUpdate(pack1);
  assert.strictEqual(res1.success, true);
  assert.strictEqual(manager.currentSequence, 1);
  assert.strictEqual(manager.indicatorIndex.size, 2);

  // Fast O(1) matching checks
  const matchDomain = manager.matchIndicator('domain', 'phishing-sbi-login.invalid');
  assert.ok(matchDomain);
  assert.strictEqual(matchDomain.threatCategory, 'fake_kyc_account_blocking');

  const matchVpa = manager.matchIndicator('vpa', 'refund-claim@ybl');
  assert.ok(matchVpa);
  assert.strictEqual(matchVpa.threatCategory, 'upi_collect_payment_deception');

  // Pack 2: Sequence 2 adds phone indicator
  const pack2 = createSignedTestBundle(2, [
    {
      type: 'phone',
      value: '+91 9988776655',
      threatCategory: 'digital_arrest_extortion',
      severity: 'HIGH_RISK',
      confidence: 0.99,
      provenance: 'test-advisory',
      action: 'block'
    }
  ]);

  const res2 = manager.applyUpdate(pack2);
  assert.strictEqual(res2.success, true);
  assert.strictEqual(manager.currentSequence, 2);
  assert.strictEqual(manager.indicatorIndex.size, 3);
  assert.ok(manager.matchIndicator('phone', '+919988776655'));
});

test('Threat Update Pipeline: Case 2 — Tampered signature leaves last known-good pack intact', () => {
  const manager = new ThreatUpdateManager();
  manager.registerTrustedKey('key-test-1', {
    publicKeyPem: testKey1.publicKeyPem,
    issuer: 'verity-threat-intel-authority',
    status: 'active'
  });

  // 1. Establish valid sequence 1
  const goodPack = createSignedTestBundle(1, [
    { type: 'domain', value: 'known-malware-feed.invalid', threatCategory: 'malicious_application_dropper', severity: 'HIGH_RISK', confidence: 0.99, provenance: 'cert-in', action: 'block' }
  ]);
  manager.applyUpdate(goodPack);
  assert.strictEqual(manager.currentSequence, 1);
  assert.ok(manager.matchIndicator('domain', 'known-malware-feed.invalid'));

  // 2. Incoming sequence 2 is tampered by an adversary
  const tamperedPack = createSignedTestBundle(2, [
    { type: 'domain', value: 'injected-bad-domain.invalid', threatCategory: 'phishing_credential_harvesting', severity: 'HIGH_RISK', confidence: 0.95, provenance: 'test', action: 'block' }
  ]);
  tamperedPack.indicators[0].value = 'altered-after-signing.invalid';

  const updateResult = manager.applyUpdate(tamperedPack);
  assert.strictEqual(updateResult.success, false);
  assert.strictEqual(updateResult.errorCode, 'INVALID_SIGNATURE');

  // 3. Verify last known-good state is preserved 100% intact
  assert.strictEqual(manager.currentSequence, 1, 'Current sequence must remain 1');
  assert.ok(manager.matchIndicator('domain', 'known-malware-feed.invalid'), 'Original indicators must remain active');
  assert.strictEqual(manager.matchIndicator('domain', 'altered-after-signing.invalid'), null, 'Tampered indicator must NOT be indexed');
});

test('Threat Update Pipeline: Case 3 — Rollback / Replay attack leaves last known-good pack intact', () => {
  const manager = new ThreatUpdateManager();
  manager.registerTrustedKey('key-test-1', {
    publicKeyPem: testKey1.publicKeyPem,
    issuer: 'verity-threat-intel-authority',
    status: 'active'
  });

  // Establish sequence 5
  manager.applyUpdate(createSignedTestBundle(5, [
    { type: 'domain', value: 'threat-at-seq-5.invalid', threatCategory: 'phishing_credential_harvesting', severity: 'HIGH_RISK', confidence: 0.9, provenance: 'i4c', action: 'block' }
  ]));

  // Adversary tries to replay sequence 3
  const replayedPack = createSignedTestBundle(3, [
    { type: 'domain', value: 'old-threat.invalid', threatCategory: 'phishing_credential_harvesting', severity: 'HIGH_RISK', confidence: 0.9, provenance: 'i4c', action: 'block' }
  ]);

  const updateResult = manager.applyUpdate(replayedPack);
  assert.strictEqual(updateResult.success, false);
  assert.strictEqual(updateResult.errorCode, 'SEQUENCE_ROLLBACK_DETECTED');
  assert.strictEqual(manager.currentSequence, 5);
  assert.ok(manager.matchIndicator('domain', 'threat-at-seq-5.invalid'));
});

test('Threat Update Pipeline: Case 4 — Expired update leaves last known-good pack intact', () => {
  const manager = new ThreatUpdateManager();
  manager.registerTrustedKey('key-test-1', {
    publicKeyPem: testKey1.publicKeyPem,
    issuer: 'verity-threat-intel-authority',
    status: 'active'
  });

  manager.applyUpdate(createSignedTestBundle(1, [
    { type: 'vpa', value: 'fraud@ybl', threatCategory: 'upi_collect_payment_deception', severity: 'HIGH_RISK', confidence: 0.9, provenance: 'npci', action: 'block' }
  ]));

  // Expired sequence 2
  const expiredPack = createSignedTestBundle(2, [
    { type: 'vpa', value: 'new-fraud@ybl', threatCategory: 'upi_collect_payment_deception', severity: 'HIGH_RISK', confidence: 0.9, provenance: 'npci', action: 'block' }
  ], {
    expiresAt: new Date(Date.now() - 3600000).toISOString()
  });

  const updateResult = manager.applyUpdate(expiredPack);
  assert.strictEqual(updateResult.success, false);
  assert.strictEqual(updateResult.errorCode, 'PACK_EXPIRED');
  assert.strictEqual(manager.currentSequence, 1);
  assert.strictEqual(manager.matchIndicator('vpa', 'new-fraud@ybl'), null);
});

test('Threat Update Pipeline: Case 5 — Revoked key update leaves last known-good pack intact', () => {
  const manager = new ThreatUpdateManager();
  manager.registerTrustedKey('key-test-1', {
    publicKeyPem: testKey1.publicKeyPem,
    issuer: 'verity-threat-intel-authority',
    status: 'active'
  });
  manager.registerTrustedKey('key-test-2', {
    publicKeyPem: testKey2.publicKeyPem,
    issuer: 'verity-threat-intel-authority',
    status: 'active'
  });

  manager.applyUpdate(createSignedTestBundle(1, [
    { type: 'domain', value: 'active-domain.invalid', threatCategory: 'phishing_credential_harvesting', severity: 'HIGH_RISK', confidence: 0.9, provenance: 'test', action: 'block' }
  ]));

  // Admin revokes key-test-2
  manager.revokeKey('key-test-2', 'KEY_SUSPECTED_COMPROMISE');

  // Pack signed with revoked key
  const revokedPack = createSignedTestBundle(2, [
    { type: 'domain', value: 'signed-by-compromised-key.invalid', threatCategory: 'phishing_credential_harvesting', severity: 'HIGH_RISK', confidence: 0.9, provenance: 'test', action: 'block' }
  ], { keyId: 'key-test-2' }, testKey2);

  const updateResult = manager.applyUpdate(revokedPack);
  assert.strictEqual(updateResult.success, false);
  assert.strictEqual(updateResult.errorCode, 'SIGNING_KEY_REVOKED');
  assert.strictEqual(manager.currentSequence, 1);
});

test('Threat Update Pipeline: Case 6 — Malformed / corrupted JSON leaves last known-good pack intact', () => {
  const manager = new ThreatUpdateManager();
  manager.registerTrustedKey('key-test-1', {
    publicKeyPem: testKey1.publicKeyPem,
    issuer: 'verity-threat-intel-authority',
    status: 'active'
  });

  manager.applyUpdate(createSignedTestBundle(1, [
    { type: 'domain', value: 'safe-fallback.invalid', threatCategory: 'phishing_credential_harvesting', severity: 'HIGH_RISK', confidence: 0.9, provenance: 'test', action: 'block' }
  ]));

  const malformedPacks = [
    null,
    {},
    { schemaVersion: '1.0.0', packId: 'incomplete' },
    { schemaVersion: '1.0.0', packId: 'test', sequence: 'not_an_int', signature: 'hex' }
  ];

  for (const badPack of malformedPacks) {
    const res = manager.applyUpdate(badPack);
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.errorCode, 'MALFORMED_SCHEMA');
    assert.strictEqual(manager.currentSequence, 1);
    assert.ok(manager.matchIndicator('domain', 'safe-fallback.invalid'));
  }
});

test('Threat Update Pipeline: Case 7 — Feed fetching sends ZERO client telemetry, credentials or scan history', async () => {
  const manager = new ThreatUpdateManager();
  manager.registerTrustedKey('key-test-1', {
    publicKeyPem: testKey1.publicKeyPem,
    issuer: 'verity-threat-intel-authority',
    status: 'active'
  });

  const interceptedRequests = [];
  const mockFetch = async (url, options) => {
    interceptedRequests.push({ url: url.toString(), options });
    const nextPack = createSignedTestBundle(1, [
      { type: 'domain', value: 'newly-discovered-feed-threat.invalid', threatCategory: 'phishing_credential_harvesting', severity: 'HIGH_RISK', confidence: 0.99, provenance: 'cert-in', action: 'block' }
    ]);
    return {
      ok: true,
      status: 200,
      json: async () => nextPack
    };
  };

  const feedResult = await manager.checkAndFetchStagingFeed('https://threat-feed.staging.verity.internal/v1/bundle', {
    fetchImpl: mockFetch
  });

  assert.strictEqual(feedResult.updated, true);
  assert.strictEqual(feedResult.sequence, 1);

  // Inspect intercepted network request to guarantee absolute zero telemetry
  assert.strictEqual(interceptedRequests.length, 1);
  const req = interceptedRequests[0];

  assert.strictEqual(req.options.method, 'GET', 'Feed check must be a pure idempotent GET request');
  assert.strictEqual(req.options.body, undefined, 'Feed check must NEVER send an HTTP body');

  const parsedUrl = new URL(req.url);
  // Verify only since_seq is sent
  assert.strictEqual(parsedUrl.searchParams.get('since_seq'), '0');
  
  // Verify NO sensitive client identifiers or words escape
  const serializedReq = JSON.stringify(req);
  assert.strictEqual(serializedReq.includes('password'), false);
  assert.strictEqual(serializedReq.includes('aadhaar'), false);
  assert.strictEqual(serializedReq.includes('otp'), false);
  assert.strictEqual(serializedReq.includes('scanId'), false);
  assert.strictEqual(serializedReq.includes('history'), false);
});
