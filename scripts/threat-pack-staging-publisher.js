#!/usr/bin/env node
/**
 * scripts/threat-pack-staging-publisher.js — Local Staging Publisher & Bundle Validator
 *
 * Implements a staging publisher that signs, validates, and outputs deterministic
 * authenticated threat packs for local simulation and integration testing.
 *
 * SAFETY INVARIANT:
 * Uses exclusively ephemeral or local staging test keys.
 * Never commits private production keys, institutional credentials, or production secrets.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  THREAT_PACK_SCHEMA_VERSION,
  generateTestEd25519KeyPair,
  signThreatPackForTest,
  verifyThreatPack,
  canonicalJsonStringify
} from '../verity-extension/shared/threat-pack-verifier.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const stagingDir = path.resolve(rootDir, 'sample_data/staging_feed');

export const STAGING_ISSUER = 'verity-staging-authority';
export const STAGING_KEY_ID = 'staging-ed25519-key-2026';

/**
 * Generates and saves staging key pair to local sample_data/staging_feed/keys (ignored by git).
 */
export function ensureStagingKeys() {
  const keysDir = path.join(stagingDir, 'keys');
  if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
  }

  const pubPath = path.join(keysDir, 'staging_pub.pem');
  const privPath = path.join(keysDir, 'staging_priv.pem');

  if (fs.existsSync(pubPath) && fs.existsSync(privPath)) {
    return {
      publicKeyPem: fs.readFileSync(pubPath, 'utf8'),
      privateKeyPem: fs.readFileSync(privPath, 'utf8')
    };
  }

  console.log('[StagingPublisher] Generating fresh staging Ed25519 key pair...');
  const keys = generateTestEd25519KeyPair();
  fs.writeFileSync(pubPath, keys.publicKeyPem, 'utf8');
  fs.writeFileSync(privPath, keys.privateKeyPem, 'utf8');
  console.log('[StagingPublisher] Staging keys saved to:', keysDir);
  return keys;
}

/**
 * Creates and cryptographically signs a staging threat bundle.
 *
 * @param {object} params
 * @param {string} params.packId
 * @param {number} params.sequence
 * @param {Array<object>} params.indicators
 * @param {Array<object>} [params.revocations=[]]
 * @param {number} [params.validityDays=7]
 * @param {string} params.privateKeyPem
 * @returns {object} Signed bundle
 */
export function buildStagingBundle(params) {
  const now = Date.now();
  const expiresAt = new Date(now + (params.validityDays || 7) * 86400000).toISOString();

  const unsigned = {
    schemaVersion: THREAT_PACK_SCHEMA_VERSION,
    packId: params.packId || `staging-pack-seq-${params.sequence}`,
    sequence: params.sequence,
    issuer: STAGING_ISSUER,
    keyId: STAGING_KEY_ID,
    createdAt: new Date(now).toISOString(),
    expiresAt,
    indicators: params.indicators || [],
    revocations: params.revocations || []
  };

  return signThreatPackForTest(unsigned, params.privateKeyPem);
}

/**
 * Validates a bundle against a public key before publishing.
 *
 * @param {object} bundle
 * @param {string} publicKeyPem
 * @param {number} currentSequence
 * @returns {object} Verification outcome
 */
export function validateBundle(bundle, publicKeyPem, currentSequence = 0) {
  const keystore = new Map([
    [
      STAGING_KEY_ID,
      {
        publicKeyPem,
        issuer: STAGING_ISSUER,
        status: 'active'
      }
    ]
  ]);

  return verifyThreatPack(bundle, {
    trustedKeys: keystore,
    currentSequence
  });
}

/**
 * Publishes a bundle to the staging feed directory.
 *
 * @param {object} bundle
 * @param {string} [outputDir=stagingDir]
 * @returns {string} File path written
 */
export function publishStagingBundle(bundle, outputDir = stagingDir) {
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const filePath = path.join(outputDir, `threat_pack_seq_${bundle.sequence}.json`);
  const canonical = canonicalJsonStringify(bundle);
  fs.writeFileSync(filePath, JSON.stringify(bundle, null, 2), 'utf8');

  // Also write latest pointer
  const latestPath = path.join(outputDir, 'latest.json');
  fs.writeFileSync(latestPath, JSON.stringify(bundle, null, 2), 'utf8');

  console.log(`[StagingPublisher] Published threat pack sequence ${bundle.sequence} to: ${filePath}`);
  return filePath;
}

// CLI Execution Support
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log('=== VERITY STAGING THREAT PACK PUBLISHER ===');
  const keys = ensureStagingKeys();

  const sampleIndicators = [
    {
      type: 'domain',
      value: 'sbi-reward-claim-portal.invalid',
      threatCategory: 'fake_refund_cashback_reward',
      severity: 'HIGH_RISK',
      confidence: 0.98,
      provenance: 'staging-fixture-cert-in',
      action: 'block'
    },
    {
      type: 'vpa',
      value: 'electricity-bill-refund@ybl',
      threatCategory: 'upi_collect_payment_deception',
      severity: 'HIGH_RISK',
      confidence: 0.96,
      provenance: 'staging-fixture-npci',
      action: 'block'
    },
    {
      type: 'phone',
      value: '+919988776655',
      threatCategory: 'digital_arrest_extortion',
      severity: 'HIGH_RISK',
      confidence: 0.99,
      provenance: 'staging-fixture-i4c',
      action: 'block'
    }
  ];

  const bundle = buildStagingBundle({
    sequence: 1,
    indicators: sampleIndicators,
    privateKeyPem: keys.privateKeyPem
  });

  const validation = validateBundle(bundle, keys.publicKeyPem, 0);
  if (!validation.verified) {
    console.error('[StagingPublisher] Validation failed:', validation.reason);
    process.exit(1);
  }

  publishStagingBundle(bundle);
  console.log('[StagingPublisher] Staging pipeline execution verified successfully.');
}
