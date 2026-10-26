/**
 * shared/threat-pack-verifier.js — Cryptographically Signed Threat-Pack Verification Interface
 *
 * Implements authenticated threat intelligence bundle verification using standard Ed25519
 * digital signatures (RFC 8032) via standard node:crypto (and Web Crypto API compatibility).
 *
 * Design Invariants:
 * 1. Zero Custom Cryptography: Relies exclusively on standard, maintained Ed25519 primitives.
 * 2. Never Trust Unsigned Packs: Rejects unsigned bundles or untrusted signing keys.
 * 3. Anti-Rollback / Replay Prevention: Enforces strictly monotonically increasing sequence numbers.
 * 4. Expiry & Clock Skew Guard: Rejects expired threat packs and future-dated bundles.
 * 5. Key Revocation & Rotation: Validates issuer identity and signing key status against a trusted registry.
 * 6. Indicator Normalization: Enforces canonical, sanitized formats before indicators are accepted.
 *
 * Universal portability: Zero external proprietary dependencies.
 */

import crypto from 'node:crypto';

export const THREAT_PACK_SCHEMA_VERSION = '1.0.0';

/**
 * Valid indicator types supported by the Verity engine.
 */
export const ALLOWED_INDICATOR_TYPES = Object.freeze([
  'domain',
  'vpa',
  'phone',
  'url_pattern',
  'apk_sha256'
]);

/**
 * Generates canonical JSON string for deterministic cryptographic signing and hashing.
 * Sorts object keys recursively.
 *
 * @param {*} data
 * @returns {string} Canonical JSON representation
 */
export function canonicalJsonStringify(data) {
  if (data === null || typeof data !== 'object') {
    return JSON.stringify(data);
  }

  if (Array.isArray(data)) {
    return '[' + data.map(canonicalJsonStringify).join(',') + ']';
  }

  const sortedKeys = Object.keys(data).sort();
  const entries = sortedKeys.map(k => `${JSON.stringify(k)}:${canonicalJsonStringify(data[k])}`);
  return '{' + entries.join(',') + '}';
}

/**
 * Normalizes an indicator value according to its type.
 *
 * @param {string} type
 * @param {string} rawValue
 * @returns {string} Normalized indicator string
 */
export function normalizeIndicatorValue(type, rawValue) {
  if (typeof rawValue !== 'string' || !rawValue.trim()) {
    throw new Error(`Indicator value must be a non-empty string. Got: "${rawValue}".`);
  }

  const val = rawValue.trim();

  switch (type) {
    case 'domain':
      return val.toLowerCase().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    case 'vpa':
      return val.toLowerCase();
    case 'phone':
      return val.replace(/[^\d+]/g, '');
    case 'apk_sha256':
      return val.toLowerCase();
    case 'url_pattern':
      return val.toLowerCase();
    default:
      return val;
  }
}

/**
 * Validates the syntactic structure of an unverified threat pack.
 *
 * @param {object} pack
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateThreatPackSchema(pack) {
  const errors = [];

  if (!pack || typeof pack !== 'object') {
    return { valid: false, errors: ['Threat pack must be a non-null object.'] };
  }

  if (pack.schemaVersion !== THREAT_PACK_SCHEMA_VERSION) {
    errors.push(`Invalid schemaVersion: expected "${THREAT_PACK_SCHEMA_VERSION}", got "${pack.schemaVersion}".`);
  }

  if (!pack.packId || typeof pack.packId !== 'string') {
    errors.push('packId must be a non-empty string identifier.');
  }

  if (typeof pack.sequence !== 'number' || !Number.isInteger(pack.sequence) || pack.sequence < 1) {
    errors.push(`sequence must be a positive integer, got: "${pack.sequence}".`);
  }

  if (!pack.issuer || typeof pack.issuer !== 'string') {
    errors.push('issuer identity must be specified.');
  }

  if (!pack.keyId || typeof pack.keyId !== 'string') {
    errors.push('keyId must be specified.');
  }

  if (!pack.createdAt || isNaN(Date.parse(pack.createdAt))) {
    errors.push('createdAt must be a valid ISO-8601 timestamp.');
  }

  if (!pack.expiresAt || isNaN(Date.parse(pack.expiresAt))) {
    errors.push('expiresAt must be a valid ISO-8601 timestamp.');
  }

  if (!Array.isArray(pack.indicators)) {
    errors.push('indicators must be an array.');
  } else {
    pack.indicators.forEach((ind, idx) => {
      if (!ind || typeof ind !== 'object') {
        errors.push(`Indicator [${idx}] must be an object.`);
        return;
      }
      if (!ALLOWED_INDICATOR_TYPES.includes(ind.type)) {
        errors.push(`Indicator [${idx}] has invalid type "${ind.type}".`);
      }
      if (!ind.value || typeof ind.value !== 'string') {
        errors.push(`Indicator [${idx}] has invalid or missing value.`);
      }
      if (typeof ind.confidence !== 'number' || ind.confidence < 0 || ind.confidence > 1) {
        errors.push(`Indicator [${idx}] confidence must be a number between 0 and 1.`);
      }
    });
  }

  if (!pack.signature || typeof pack.signature !== 'string') {
    errors.push('Threat pack is missing required cryptographic signature.');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Extracts the signable payload by removing the signature field.
 *
 * @param {object} pack
 * @returns {object} Canonical payload ready for signing or verification
 */
export function extractSignablePayload(pack) {
  const { signature, ...signable } = pack;
  return signable;
}

/**
 * Verifies a threat pack against trusted public keys, checking authenticity,
 * rollback protection, expiry, and key status.
 *
 * @param {object} pack - Unverified incoming threat pack
 * @param {object} options
 * @param {Map<string, { publicKeyPem: string, issuer: string, status: 'active'|'revoked' }>} options.trustedKeys
 * @param {number} [options.currentSequence=0] - Current highest installed sequence
 * @param {number} [options.currentTimestamp] - Reference timestamp (defaults to Date.now())
 * @param {number} [options.maxClockSkewMs=120000] - 2 minutes allowed clock skew
 * @returns {{ verified: boolean, errorCode?: string, reason?: string, verifiedPack?: object }}
 */
export function verifyThreatPack(pack, options = {}) {
  const {
    trustedKeys,
    currentSequence = 0,
    currentTimestamp = Date.now(),
    maxClockSkewMs = 120000
  } = options;

  // 1. Schema Validation
  const schemaResult = validateThreatPackSchema(pack);
  if (!schemaResult.valid) {
    return {
      verified: false,
      errorCode: 'MALFORMED_SCHEMA',
      reason: `Threat pack schema invalid: ${schemaResult.errors.join('; ')}`
    };
  }

  // 2. Issuer and Key Lookup
  if (!trustedKeys || typeof trustedKeys.get !== 'function') {
    return {
      verified: false,
      errorCode: 'KEYSTORE_UNAVAILABLE',
      reason: 'Trusted public keystore was not provided or is invalid.'
    };
  }

  const keyMeta = trustedKeys.get(pack.keyId);
  if (!keyMeta) {
    return {
      verified: false,
      errorCode: 'UNTRUSTED_KEY_ID',
      reason: `Key ID "${pack.keyId}" is not present in the local trusted keystore.`
    };
  }

  if (keyMeta.issuer !== pack.issuer) {
    return {
      verified: false,
      errorCode: 'ISSUER_MISMATCH',
      reason: `Pack claims issuer "${pack.issuer}", but Key ID "${pack.keyId}" is registered to "${keyMeta.issuer}".`
    };
  }

  if (keyMeta.status === 'revoked') {
    return {
      verified: false,
      errorCode: 'SIGNING_KEY_REVOKED',
      reason: `Signing key "${pack.keyId}" has been revoked and cannot be used for updates.`
    };
  }

  // 3. Rollback & Sequence Protection
  if (pack.sequence <= currentSequence) {
    return {
      verified: false,
      errorCode: 'SEQUENCE_ROLLBACK_DETECTED',
      reason: `Pack sequence ${pack.sequence} is <= current active sequence ${currentSequence}. Replay or rollback blocked.`
    };
  }

  // 4. Temporal Integrity (Expiry & Clock Skew)
  const createdMs = Date.parse(pack.createdAt);
  const expiresMs = Date.parse(pack.expiresAt);

  if (createdMs > currentTimestamp + maxClockSkewMs) {
    return {
      verified: false,
      errorCode: 'FUTURE_TIMESTAMP_DETECTED',
      reason: `Pack creation time is in the future beyond acceptable clock skew.`
    };
  }

  if (currentTimestamp >= expiresMs) {
    return {
      verified: false,
      errorCode: 'PACK_EXPIRED',
      reason: `Threat pack expired at ${pack.expiresAt} (current time: ${new Date(currentTimestamp).toISOString()}).`
    };
  }

  // 5. Cryptographic Ed25519 Signature Verification
  try {
    const signablePayload = extractSignablePayload(pack);
    const canonicalString = canonicalJsonStringify(signablePayload);
    const dataBuffer = Buffer.from(canonicalString, 'utf-8');
    const signatureBuffer = Buffer.from(pack.signature, 'hex');

    const isSignatureValid = crypto.verify(
      null, // Ed25519 does not take a digest algorithm name
      dataBuffer,
      keyMeta.publicKeyPem,
      signatureBuffer
    );

    if (!isSignatureValid) {
      return {
        verified: false,
        errorCode: 'INVALID_SIGNATURE',
        reason: 'Cryptographic signature verification failed. Payload may be tampered or corrupted.'
      };
    }
  } catch (err) {
    return {
      verified: false,
      errorCode: 'CRYPTO_VERIFICATION_ERROR',
      reason: `Cryptographic verification threw an unexpected error: ${err.message}`
    };
  }

  // 6. Normalization & Sanitization of Indicators
  const verifiedIndicators = pack.indicators.map(ind => ({
    type: ind.type,
    value: normalizeIndicatorValue(ind.type, ind.value),
    threatCategory: ind.threatCategory,
    severity: ind.severity,
    confidence: ind.confidence,
    provenance: ind.provenance,
    action: ind.action || 'block'
  }));

  return {
    verified: true,
    verifiedPack: {
      packId: pack.packId,
      sequence: pack.sequence,
      issuer: pack.issuer,
      keyId: pack.keyId,
      createdAt: pack.createdAt,
      expiresAt: pack.expiresAt,
      indicators: verifiedIndicators,
      revocations: Array.isArray(pack.revocations) ? pack.revocations : []
    }
  };
}

/**
 * Test helper to generate standard Ed25519 keypairs and sign bundles for local testing.
 * NOT for production key generation.
 *
 * @returns {{ publicKeyPem: string, privateKeyPem: string }}
 */
export function generateTestEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

/**
 * Test helper to cryptographically sign a threat pack payload with an Ed25519 private key.
 *
 * @param {object} unsignedPack
 * @param {string} privateKeyPem
 * @returns {object} Threat pack with valid hex signature
 */
export function signThreatPackForTest(unsignedPack, privateKeyPem) {
  const signable = extractSignablePayload(unsignedPack);
  const canonicalString = canonicalJsonStringify(signable);
  const dataBuffer = Buffer.from(canonicalString, 'utf-8');

  const signatureBuffer = crypto.sign(null, dataBuffer, privateKeyPem);
  return {
    ...signable,
    signature: signatureBuffer.toString('hex')
  };
}

export default {
  THREAT_PACK_SCHEMA_VERSION,
  ALLOWED_INDICATOR_TYPES,
  canonicalJsonStringify,
  normalizeIndicatorValue,
  validateThreatPackSchema,
  verifyThreatPack,
  generateTestEd25519KeyPair,
  signThreatPackForTest
};
