/**
 * rdap-sentinel.js — Universal ICANN / IANA RDAP Newly-Registered-Domain (NRD) Sentinel
 *
 * 100% Free Forever, standard-compliant (RFC 7480-7484) domain age evaluator.
 * Detects newly registered domains (NRDs <= 14 days old) without any commercial WHOIS API keys.
 */

import { getDomain } from '../shared/psl.js';

// In-memory LRU Cache: domain -> { registrationDate: string, timestamp: number }
const rdapCache = new Map();
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_CACHE_ENTRIES = 500;

/**
 * Pure, deterministic evaluation of domain age risk against universal invariants.
 *
 * @param {string|number} registrationIsoDate - ISO 8601 string or ms timestamp
 * @param {number} [nowMs=Date.now()] - Current epoch ms
 * @param {boolean} [hasSensitiveDomOrKeywords=false] - Whether page contains credential forms or financial terms
 * @returns {{
 *   isNewlyRegistered: boolean,
 *   ageDays: number|null,
 *   score: number,
 *   signal: string|null,
 *   hardOverride: boolean,
 *   reason: string|null
 * }}
 */
export function evaluateDomainAgeRisk(registrationIsoDate, nowMs = Date.now(), hasSensitiveDomOrKeywords = false) {
  if (!registrationIsoDate) {
    return {
      isNewlyRegistered: false,
      ageDays: null,
      score: 0,
      signal: null,
      hardOverride: false,
      reason: null
    };
  }

  const regTimestamp = typeof registrationIsoDate === 'number'
    ? registrationIsoDate
    : Date.parse(registrationIsoDate);

  if (isNaN(regTimestamp)) {
    return {
      isNewlyRegistered: false,
      ageDays: null,
      score: 0,
      signal: null,
      hardOverride: false,
      reason: null
    };
  }

  const ageDays = Math.max(0, Math.floor((nowMs - regTimestamp) / (1000 * 60 * 60 * 24)));

  if (ageDays >= 0 && ageDays <= 14) {
    if (hasSensitiveDomOrKeywords) {
      return {
        isNewlyRegistered: true,
        ageDays,
        score: 85,
        signal: 'SIG_UNIVERSAL_NRD_CREDENTIAL_TRAP',
        hardOverride: true,
        reason: `Universal NRD Trap: Domain registered only ${ageDays} day(s) ago requesting sensitive credentials.`
      };
    }
    return {
      isNewlyRegistered: true,
      ageDays,
      score: 45,
      signal: 'SIG_NEWLY_REGISTERED_DOMAIN_CAUTION',
      hardOverride: false,
      reason: `Newly registered domain advisory: Domain was registered ${ageDays} day(s) ago.`
    };
  }

  return {
    isNewlyRegistered: false,
    ageDays,
    score: 0,
    signal: null,
    hardOverride: false,
    reason: null
  };
}

/**
 * Queries authoritative ICANN RDAP server with strict 450ms budget and LRU caching.
 *
 * @param {string} hostname - Target hostname
 * @param {Function} [fetchImpl=globalThis.fetch] - Custom or global fetch
 * @param {number} [nowMs=Date.now()] - Current time
 * @param {boolean} [hasSensitiveDomOrKeywords=false] - Sensitive form flag
 * @returns {Promise<object|null>}
 */
export async function queryFreeRdapDomainAge(
  hostname,
  fetchImpl = (typeof globalThis !== 'undefined' ? globalThis.fetch : null),
  nowMs = Date.now(),
  hasSensitiveDomOrKeywords = false
) {
  if (!hostname || typeof hostname !== 'string') return null;

  const cleanHost = hostname.toLowerCase().replace(/^www\./, '');
  const domain = getDomain(cleanHost) || cleanHost;
  if (!domain || !domain.includes('.') || /^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
    return null; // IP address or single-token host
  }

  // 1. Check in-memory LRU cache
  const cached = rdapCache.get(domain);
  if (cached && (nowMs - cached.timestamp < CACHE_TTL_MS)) {
    return evaluateDomainAgeRisk(cached.registrationDate, nowMs, hasSensitiveDomOrKeywords);
  }

  if (typeof fetchImpl !== 'function') {
    return null;
  }

  // 2. Query free ICANN RDAP bootstrap redirector
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), 450) : null;

  try {
    const rdapEndpoint = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
    const res = await fetchImpl(rdapEndpoint, {
      headers: { 'Accept': 'application/rdap+json, application/json' },
      signal: controller ? controller.signal : undefined
    });

    if (timeoutId) clearTimeout(timeoutId);

    if (res && res.ok) {
      const data = await res.json();
      const events = Array.isArray(data?.events) ? data.events : [];
      const regEvent = events.find(e => e && (e.eventAction === 'registration' || e.eventAction === 'created'));
      const regDate = regEvent ? regEvent.eventDate : null;

      if (regDate) {
        // Update LRU cache
        if (rdapCache.size >= MAX_CACHE_ENTRIES) {
          const firstKey = rdapCache.keys().next().value;
          rdapCache.delete(firstKey);
        }
        rdapCache.set(domain, { registrationDate: regDate, timestamp: nowMs });
        return evaluateDomainAgeRisk(regDate, nowMs, hasSensitiveDomOrKeywords);
      }
    }
  } catch (_) {
    // Graceful offline fallback on timeout or connection error
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }

  return null;
}

export default {
  evaluateDomainAgeRisk,
  queryFreeRdapDomainAge
};
