/**
 * reputation.js — Threat Intelligence with Local High-Performance Feed Indexing
 *
 * Provides real-time, on-device threat intelligence lookups against known malware,
 * phishing, and scam domains. Operates with zero-telemetry by default using local
 * pre-indexed feeds, sub-millisecond lookup latency, and graceful offline fallback.
 */

import seedThreats from '../config/threat_intel_seed.js';
import { getDomain } from '../shared/psl.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { isTrustedTopDomain } from './rules.js';
import { normalizeConfusables } from './homograph-detector.js';

// ── In-Memory Threat Database ───────────────────────────────────────────────
// hostname / root domain → source string (e.g. 'URLhaus (Malvertising Rotator)')
const threatDatabase = new Map();

// In-memory query result cache: hostname → { result, timestamp }
const queryCache = new Map();
const CACHE_TTL_SAFE_MS = 30 * 60 * 1000;       // 30 minutes for safe domains
const CACHE_TTL_MALWARE_MS = 4 * 60 * 60 * 1000; // 4 hours for verified malware

/**
 * Populate local threat database from seed list.
 */
function loadSeedData() {
  if (Array.isArray(seedThreats)) {
    for (const item of seedThreats) {
      if (item && item.domain) {
        threatDatabase.set(item.domain.toLowerCase(), item.source || 'Threat Intelligence (Known Feed)');
      }
    }
  }
}
loadSeedData();

/**
 * Hydrate dynamic threat feeds stored in chrome.storage.local (if running in extension).
 */
export async function hydrateThreatStorage() {
  if (typeof chrome !== 'undefined' && chrome.storage?.local) {
    try {
      const data = await chrome.storage.local.get(['verity_threat_intel_cache']);
      const dynamicList = data?.verity_threat_intel_cache;
      if (Array.isArray(dynamicList)) {
        for (const item of dynamicList) {
          if (item && item.domain) {
            threatDatabase.set(item.domain.toLowerCase(), item.source || 'Threat Intelligence (Dynamic Feed)');
          }
        }
      }
    } catch (_) {}
  }
}

// Automatically attempt hydration
hydrateThreatStorage();

/**
 * Threat intel lookup toggle.
 * Local threat intelligence engine is ACTIVE by default.
 */
export const ENABLE_REMOTE_THREAT_INTEL = true;

/**
 * Look up in-memory query cache.
 */
function getCachedVerdict(hostname) {
  const entry = queryCache.get(hostname);
  if (!entry) return null;
  const ttl = entry.result.malware ? CACHE_TTL_MALWARE_MS : CACHE_TTL_SAFE_MS;
  if (Date.now() - entry.timestamp > ttl) {
    queryCache.delete(hostname);
    return null;
  }
  return entry.result;
}

/**
 * Store in query cache with LRU size limit.
 */
function setCachedVerdict(hostname, result) {
  queryCache.set(hostname, { result, timestamp: Date.now() });
  if (queryCache.size > 2000) {
    const firstKey = queryCache.keys().next().value;
    queryCache.delete(firstKey);
  }
}

/**
 * Check if a hostname or its parent domains exist in the threat intelligence database.
 * @param {string} hostname
 * @returns {{ malware: boolean, source: string|null }}
 */
export function lookupThreatDatabase(hostname) {
  if (!hostname) return { malware: false, source: null };
  const h = hostname.toLowerCase();

  // 1. Direct hostname match
  if (threatDatabase.has(h)) {
    return { malware: true, source: threatDatabase.get(h) };
  }

  // 2. Root registered domain match (e.g., sub.bad-domain.com -> bad-domain.com)
  const rootDomain = getDomain(h);
  if (rootDomain && threatDatabase.has(rootDomain)) {
    return { malware: true, source: threatDatabase.get(rootDomain) };
  }

  // 3. Normalized confusable domain match (e.g., homoglyph spoofing of a malware host)
  const normalized = normalizeConfusables(h);
  if (normalized && normalized !== h) {
    if (threatDatabase.has(normalized)) {
      return { malware: true, source: threatDatabase.get(normalized) };
    }
    const normRoot = getDomain(normalized);
    if (normRoot && threatDatabase.has(normRoot)) {
      return { malware: true, source: threatDatabase.get(normRoot) };
    }
  }

  // 4. Subdomain hierarchy check (up to 3 levels)
  const parts = h.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    const parentHost = parts.slice(i).join('.');
    if (threatDatabase.has(parentHost)) {
      return { malware: true, source: threatDatabase.get(parentHost) };
    }
  }

  return { malware: false, source: null };
}

/**
 * Check URL reputation against threat intelligence feeds.
 *
 * Guarantees:
 * 1. Allowlisted and trusted domains are exempted immediately (0 network requests, 0 latency).
 * 2. Instant sub-millisecond local threat database matching.
 * 3. Graceful offline fallback — never blocks navigation if offline.
 *
 * @param {string} url
 * @returns {Promise<{ malware: boolean, source: string|null }>}
 */
export async function checkReputation(url) {
  if (!ENABLE_REMOTE_THREAT_INTEL || !url) {
    return { malware: false, source: null };
  }

  let hostname = '';
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch (_) {
    return { malware: false, source: null };
  }

  // Allowlist & trusted top domain exemption (zero-telemetry privacy guarantee)
  if (isAllowlistedDomain(hostname) || isTrustedTopDomain(hostname)) {
    return { malware: false, source: null };
  }

  // Cache check
  const cached = getCachedVerdict(hostname);
  if (cached !== null) return cached;

  // Local threat database lookup
  const localMatch = lookupThreatDatabase(hostname);
  if (localMatch.malware) {
    setCachedVerdict(hostname, localMatch);
    return localMatch;
  }

  // Clean verdict
  const safeVerdict = { malware: false, source: null };
  setCachedVerdict(hostname, safeVerdict);
  return safeVerdict;
}

/**
 * Synchronize latest active threat feeds in background.
 * Downloads recent high-confidence malicious domains and persists to local storage.
 */
export async function syncThreatFeeds() {
  if (typeof fetch === 'undefined') return false;

  const FEED_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt';

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000); // 4s timeout

    const res = await fetch(FEED_URL, { signal: controller.signal });
    clearTimeout(timeout);

    if (res.ok) {
      const text = await res.text();
      const lines = text.split('\n');
      const newThreats = [];

      // Limit to 2,000 most recent active threats for lightweight storage
      for (let i = 0; i < lines.length && newThreats.length < 2000; i++) {
        const line = lines[i].trim();
        if (line && !line.startsWith('#') && line.includes('.')) {
          const dom = line.toLowerCase();
          threatDatabase.set(dom, 'Active Phishing Database Feed');
          newThreats.push({ domain: dom, source: 'Active Phishing Database Feed' });
        }
      }

      if (typeof chrome !== 'undefined' && chrome.storage?.local && newThreats.length > 0) {
        await chrome.storage.local.set({ verity_threat_intel_cache: newThreats });
      }
      return true;
    }
  } catch (_) {
    // Offline or network error — fail safely without disruption
  }
  return false;
}
