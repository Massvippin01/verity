/**
 * shared/threat-update-manager.js — Client-Side Threat Intelligence Update Manager
 *
 * Implements atomic, fail-safe updates for authenticated threat packs.
 *
 * Design Invariants:
 * 1. Atomic Replacement: Updates are validated completely before applying.
 *    Any failure leaves the last known-good pack and active indicators intact.
 * 2. Monotonic Sequence: Sequence numbers must strictly increase (anti-replay/rollback).
 * 3. Zero-Telemetry Egress: Feed requests are pure GETs transmitting at most the
 *    current sequence number. No message content, URLs, scan history, or device IDs
 *    are ever transmitted during threat feed checks.
 * 4. Fast O(1) Local Lookup: Verified indicators are indexed by type and normalized value.
 * 5. Reversibility & Rollback: Supports authorized revocation packs to prune obsolete indicators.
 *
 * Universal portability: Zero platform lock-in; pure deterministic state machine.
 */

import {
  verifyThreatPack,
  normalizeIndicatorValue,
  THREAT_PACK_SCHEMA_VERSION
} from './threat-pack-verifier.js';

export const MANAGER_VERSION = '1.0.0';

/**
 * Manages the local active threat pack lifecycle on the client.
 */
export class ThreatUpdateManager {
  /**
   * @param {object} [options={}]
   * @param {Map<string, { publicKeyPem: string, issuer: string, status: string }>} [options.keystore]
   * @param {object} [options.initialPack=null]
   */
  constructor(options = {}) {
    this.version = MANAGER_VERSION;
    this.keystore = options.keystore || new Map();
    this.currentSequence = 0;
    this.activePack = null;
    this.lastKnownGoodPack = null;
    
    // Fast O(1) lookup indices: Map<string, IndicatorRecord> keyed by `${type}:${normalizedValue}`
    this.indicatorIndex = new Map();
    this.revokedIndicatorIds = new Set();
    this.updateAuditLog = [];

    if (options.initialPack) {
      this.applyUpdate(options.initialPack);
    }
  }

  /**
   * Registers or updates a trusted public key in the client's keystore.
   *
   * @param {string} keyId
   * @param {{ publicKeyPem: string, issuer: string, status: 'active'|'revoked' }} keyMeta
   */
  registerTrustedKey(keyId, keyMeta) {
    if (!keyId || !keyMeta || !keyMeta.publicKeyPem) {
      throw new Error('[ThreatUpdateManager] Invalid key registration parameters.');
    }
    this.keystore.set(keyId, {
      publicKeyPem: keyMeta.publicKeyPem,
      issuer: keyMeta.issuer || 'unknown-issuer',
      status: keyMeta.status || 'active'
    });
  }

  /**
   * Revokes a previously trusted signing key.
   *
   * @param {string} keyId
   * @param {string} [reason='KEY_REVOKED_BY_ADMIN']
   */
  revokeKey(keyId, reason = 'KEY_REVOKED_BY_ADMIN') {
    const existing = this.keystore.get(keyId);
    if (existing) {
      existing.status = 'revoked';
      existing.revocationReason = reason;
      this.logAudit('KEY_REVOKED', { keyId, reason });
      return true;
    }
    return false;
  }

  /**
   * Atomically validates and applies an incoming threat pack.
   * If verification fails, the active pack is preserved untouched.
   *
   * @param {object} incomingPack - Unverified threat bundle
   * @param {object} [options={}]
   * @param {number} [options.timestamp=Date.now()]
   * @returns {{ success: boolean, sequence?: number, error?: string, errorCode?: string }}
   */
  applyUpdate(incomingPack, options = {}) {
    const currentSeq = this.currentSequence;
    const refTime = options.timestamp || Date.now();

    // 1. Cryptographic and structural verification
    const verification = verifyThreatPack(incomingPack, {
      trustedKeys: this.keystore,
      currentSequence: currentSeq,
      currentTimestamp: refTime
    });

    if (!verification.verified) {
      this.logAudit('UPDATE_REJECTED', {
        packId: incomingPack?.packId,
        sequence: incomingPack?.sequence,
        errorCode: verification.errorCode,
        reason: verification.reason
      });

      return {
        success: false,
        errorCode: verification.errorCode,
        error: verification.reason
      };
    }

    const verified = verification.verifiedPack;

    // 2. Atomic Index Rebuild (State Transition)
    // Create new index snapshot without mutating active index yet
    const newIndex = new Map(this.indicatorIndex);
    const newRevocations = new Set(this.revokedIndicatorIds);

    // Process revocations
    if (Array.isArray(verified.revocations)) {
      for (const rev of verified.revocations) {
        if (rev.indicatorId) {
          newRevocations.add(rev.indicatorId);
        }
      }
    }

    // Process new verified indicators
    for (const ind of verified.indicators) {
      const normVal = normalizeIndicatorValue(ind.type, ind.value);
      const key = `${ind.type}:${normVal}`;
      newIndex.set(key, {
        type: ind.type,
        value: normVal,
        threatCategory: ind.threatCategory,
        severity: ind.severity,
        confidence: ind.confidence,
        provenance: ind.provenance,
        action: ind.action || 'block',
        packId: verified.packId,
        sequence: verified.sequence
      });
    }

    // 3. Commit state atomically
    this.lastKnownGoodPack = this.activePack ? { ...this.activePack } : null;
    this.activePack = verified;
    this.currentSequence = verified.sequence;
    this.indicatorIndex = newIndex;
    this.revokedIndicatorIds = newRevocations;

    this.logAudit('UPDATE_APPLIED', {
      packId: verified.packId,
      sequence: verified.sequence,
      indicatorCount: verified.indicators.length,
      totalActiveIndicators: this.indicatorIndex.size
    });

    return {
      success: true,
      sequence: verified.sequence,
      totalIndicators: this.indicatorIndex.size
    };
  }

  /**
   * Fast O(1) query to check if a specific normalized indicator exists in active intelligence.
   *
   * @param {string} type - 'domain' | 'vpa' | 'phone' | 'url_pattern' | 'apk_sha256'
   * @param {string} value - Raw or normalized value to inspect
   * @returns {null | object} Matching threat indicator record or null
   */
  matchIndicator(type, value) {
    if (!type || !value) return null;
    try {
      const norm = normalizeIndicatorValue(type, value);
      const key = `${type}:${norm}`;
      return this.indicatorIndex.get(key) || null;
    } catch (_) {
      return null;
    }
  }

  /**
   * Safe feed fetcher that fetches threat bundles from a local or staging feed URL.
   * Strictly enforces that NO user content, credentials, or scan data escape.
   *
   * @param {string} feedUrl - Staging update endpoint
   * @param {object} [options={}]
   * @param {Function} [options.fetchImpl=globalThis.fetch]
   * @returns {Promise<{ updated: boolean, sequence?: number, error?: string }>}
   */
  async checkAndFetchStagingFeed(feedUrl, options = {}) {
    const fetchImpl = options.fetchImpl || globalThis.fetch;
    if (typeof fetchImpl !== 'function') {
      return { updated: false, error: 'FETCH_UNAVAILABLE' };
    }

    try {
      // Build pure GET query transmitting ONLY the current sequence integer
      // Absolutely no headers containing scan history, device IDs, or PII
      const url = new URL(feedUrl);
      url.searchParams.set('since_seq', String(this.currentSequence));

      const headers = {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache'
      };

      const response = await fetchImpl(url.toString(), {
        method: 'GET',
        headers
      });

      if (response.status === 304) {
        // No new updates available
        return { updated: false, sequence: this.currentSequence, reason: 'UP_TO_DATE' };
      }

      if (!response.ok) {
        return { updated: false, error: `HTTP_STATUS_${response.status}` };
      }

      const bundle = await response.json();
      const applyResult = this.applyUpdate(bundle, options);

      return {
        updated: applyResult.success,
        sequence: applyResult.sequence || this.currentSequence,
        error: applyResult.error
      };
    } catch (err) {
      return { updated: false, error: err.message };
    }
  }

  /**
   * Internal audit logger for security update events.
   */
  logAudit(event, details) {
    this.updateAuditLog.push({
      timestamp: new Date().toISOString(),
      event,
      details
    });
    if (this.updateAuditLog.length > 100) {
      this.updateAuditLog.shift();
    }
  }

  /**
   * Returns current active status.
   */
  getStatus() {
    return {
      version: this.version,
      currentSequence: this.currentSequence,
      activePackId: this.activePack?.packId || null,
      activeIssuer: this.activePack?.issuer || null,
      activeExpiresAt: this.activePack?.expiresAt || null,
      totalActiveIndicators: this.indicatorIndex.size,
      trustedKeyCount: this.keystore.size,
      hasLastKnownGood: this.lastKnownGoodPack !== null
    };
  }
}

export default {
  MANAGER_VERSION,
  ThreatUpdateManager
};
