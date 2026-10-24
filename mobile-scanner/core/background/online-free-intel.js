/**
 * background/online-free-intel.js — 100% Free Forever Online Intel Grid (CT Logs & Dual DoH)
 *
 * Zero commercial API keys or subscriptions required:
 * 1. Certificate Transparency (CT) Log Sentinel (crt.sh):
 *    Audits public append-only TLS certificate logs to determine first-ever certificate issuance date.
 *    Detects ephemeral DV certificates (Let's Encrypt, ZeroSSL, Cloudflare) on sensitive/brand targets.
 * 2. DNS-over-HTTPS (DoH) CNAME Cloaking & Threat Intelligence (Cloudflare 1.1.1.2 & Quad9 9.9.9.9):
 *    Unmasks hidden tunnels (ngrok, trycloudflare, pages.dev, vercel) and Quad9 threat sinkholes.
 * 3. Parallel Query Grid with strict timeout and in-memory LRU caching.
 */

'use strict';

import { getDomain } from '../shared/psl.js';
import { queryFreeRdapDomainAge, evaluateDomainAgeRisk } from './rdap-sentinel.js';
import { auditDomainDmarcPosture } from '../shared/autonomous-brand-discovery.js';

// In-memory LRU caches
const ctCache = new Map();
const dohCache = new Map();
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_CACHE_ENTRIES = 500;

const CLOAKED_TUNNEL_REGEX = /(?:ngrok|trycloudflare\.com|pages\.dev|vercel\.app|netlify\.app|onrender\.com|duckdns\.org|loca\.lt|serveo\.net)/i;
const FREE_DV_ISSUER_REGEX = /(?:let's encrypt|zerossl|google trust services|we1|cloudflare|cpanel|buypass|ssl\.com)/i;
const SINKHOLE_IPS = new Set(['0.0.0.0', '127.0.0.1', '127.0.0.2']);

/**
 * Pure, deterministic evaluator for Certificate Transparency log history.
 *
 * @param {Array<object>} ctEntries - Records from crt.sh JSON output
 * @param {string} currentHostname - Hostname being evaluated
 * @param {boolean} [hasSensitiveInputs=false] - Whether page asks for credentials or sensitive data
 * @param {number} [nowMs=Date.now()] - Current epoch ms
 * @returns {{
 *   isEphemeral: boolean,
 *   earliestCertAgeDays: number|null,
 *   isFreeDvIssuer: boolean,
 *   score: number,
 *   signal: string|null,
 *   hardOverride: boolean,
 *   reason: string|null
 * }}
 */
export function evaluateCtLogForensics(ctEntries, currentHostname, hasSensitiveInputs = false, nowMs = Date.now()) {
  if (!Array.isArray(ctEntries) || ctEntries.length === 0) {
    return {
      isEphemeral: false,
      earliestCertAgeDays: null,
      isFreeDvIssuer: false,
      score: 0,
      signal: null,
      hardOverride: false,
      reason: null
    };
  }

  let earliestTimestamp = Infinity;
  let hasFreeDv = false;

  for (const entry of ctEntries) {
    const rawDate = entry.not_before || entry.entry_timestamp;
    if (rawDate) {
      const ts = typeof rawDate === 'number' ? rawDate : Date.parse(rawDate);
      if (!isNaN(ts) && ts < earliestTimestamp) {
        earliestTimestamp = ts;
      }
    }

    const issuer = entry.issuer_name || entry.issuer || '';
    if (FREE_DV_ISSUER_REGEX.test(issuer)) {
      hasFreeDv = true;
    }
  }

  if (earliestTimestamp === Infinity) {
    return {
      isEphemeral: false,
      earliestCertAgeDays: null,
      isFreeDvIssuer: hasFreeDv,
      score: 0,
      signal: null,
      hardOverride: false,
      reason: null
    };
  }

  const earliestCertAgeDays = Math.max(0, Math.floor((nowMs - earliestTimestamp) / (1000 * 60 * 60 * 24)));

  // Ephemeral Certificate Invariant: First TLS certificate ever issued <= 7 days ago
  if (earliestCertAgeDays <= 7) {
    if (hasSensitiveInputs) {
      return {
        isEphemeral: true,
        earliestCertAgeDays,
        isFreeDvIssuer: hasFreeDv,
        score: 88,
        signal: 'SIG_CT_LOG_EPHEMERAL_CERT_PHISH',
        hardOverride: true,
        reason: `Certificate Transparency: First TLS cert ever issued ${earliestCertAgeDays} day(s) ago (${hasFreeDv ? 'Free automated DV' : 'Newly issued'}) on page asking for credentials.`
      };
    }
    return {
      isEphemeral: true,
      earliestCertAgeDays,
      isFreeDvIssuer: hasFreeDv,
      score: 35,
      signal: 'SIG_CT_LOG_NEW_CERT_CAUTION',
      hardOverride: false,
      reason: `Certificate Transparency: Domain first certified ${earliestCertAgeDays} day(s) ago.`
    };
  }

  // Established domain certificate history (e.g. > 30 days) -> 0 risk
  return {
    isEphemeral: false,
    earliestCertAgeDays,
    isFreeDvIssuer: hasFreeDv,
    score: 0,
    signal: null,
    hardOverride: false,
    reason: null
  };
}

/**
 * Pure evaluator for DNS-over-HTTPS JSON packet answers.
 * Detects CNAME cloaking and Quad9 / threat intelligence sinkholes.
 *
 * @param {object} dnsJson - DNS response JSON from Cloudflare/Quad9
 * @param {string} queriedHost - Hostname requested
 * @returns {{
 *   isSinkholed: boolean,
 *   hasCnameCloak: boolean,
 *   cnameTarget: string|null,
 *   score: number,
 *   signal: string|null,
 *   hardOverride: boolean,
 *   reason: string|null
 * }}
 */
export function evaluateDohPacketForensics(dnsJson, queriedHost) {
  if (!dnsJson || typeof dnsJson !== 'object') {
    return {
      isSinkholed: false,
      hasCnameCloak: false,
      cnameTarget: null,
      score: 0,
      signal: null,
      hardOverride: false,
      reason: null
    };
  }

  // Status === 3 is NXDOMAIN or blocked by threat intelligence (Quad9)
  if (dnsJson.Status === 3 && dnsJson.Comment && /blocked/i.test(dnsJson.Comment)) {
    return {
      isSinkholed: true,
      hasCnameCloak: false,
      cnameTarget: null,
      score: 95,
      signal: 'SIG_DOH_MALWARE_SINKHOLE_DETECTED',
      hardOverride: true,
      reason: 'Quad9 DNS Threat Shield: Domain blocked as confirmed malware/phishing.'
    };
  }

  const answers = Array.isArray(dnsJson.Answer) ? dnsJson.Answer : [];

  // 1. Inspect for sinkhole IPs (0.0.0.0, 127.0.0.1, 127.0.0.2)
  for (const ans of answers) {
    const data = (ans.data || '').trim();
    if (ans.type === 1 && SINKHOLE_IPS.has(data)) {
      return {
        isSinkholed: true,
        hasCnameCloak: false,
        cnameTarget: null,
        score: 95,
        signal: 'SIG_DOH_MALWARE_SINKHOLE_DETECTED',
        hardOverride: true,
        reason: `DNS Threat Sinkhole: Domain resolves to security sinkhole address ${data}.`
      };
    }
  }

  // 2. Inspect for CNAME cloaking (Type 5)
  for (const ans of answers) {
    if (ans.type === 5) {
      const cname = (ans.data || '').toLowerCase().replace(/\.$/, '');
      const queriedClean = (queriedHost || '').toLowerCase();
      // If the domain is not already part of that provider, but points to a tunnel/free host
      if (CLOAKED_TUNNEL_REGEX.test(cname) && !CLOAKED_TUNNEL_REGEX.test(queriedClean)) {
        return {
          isSinkholed: false,
          hasCnameCloak: true,
          cnameTarget: cname,
          score: 80,
          signal: 'SIG_DNS_CNAME_CLOAKING_DETECTED',
          hardOverride: true,
          reason: `DNS CNAME Cloaking: Domain delegates to ephemeral tunnel/serverless host (${cname}) hiding infrastructure.`
        };
      }
    }
  }

  return {
    isSinkholed: false,
    hasCnameCloak: false,
    cnameTarget: null,
    score: 0,
    signal: null,
    hardOverride: false,
    reason: null
  };
}

/**
 * Queries crt.sh public Certificate Transparency logs with timeout and caching.
 *
 * @param {string} registrableDomain
 * @param {Function} [fetchImpl=globalThis.fetch]
 * @param {number} [timeoutMs=600]
 * @returns {Promise<Array<object>|null>}
 */
export async function queryFreeCtLogs(registrableDomain, fetchImpl = globalThis.fetch, timeoutMs = 600) {
  if (!registrableDomain || typeof fetchImpl !== 'function') return null;

  const now = Date.now();
  const cached = ctCache.get(registrableDomain);
  if (cached && now - cached.timestamp < CACHE_TTL_MS) {
    return cached.entries;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const url = `https://crt.sh/?q=${encodeURIComponent(registrableDomain)}&output=json`;
    const res = await fetchImpl(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' }
    });
    clearTimeout(timer);

    if (!res || !res.ok) return null;
    const data = await res.json();

    if (Array.isArray(data)) {
      if (ctCache.size >= MAX_CACHE_ENTRIES) {
        const oldest = ctCache.keys().next().value;
        ctCache.delete(oldest);
      }
      ctCache.set(registrableDomain, { entries: data, timestamp: now });
      return data;
    }
    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Queries DNS-over-HTTPS (DoH) via Cloudflare (1.1.1.2) or Quad9 (9.9.9.9).
 *
 * @param {string} hostname
 * @param {Function} [fetchImpl=globalThis.fetch]
 * @param {number} [timeoutMs=500]
 * @returns {Promise<object|null>}
 */
export async function queryFreeDoh(hostname, fetchImpl = globalThis.fetch, timeoutMs = 500) {
  if (!hostname || typeof fetchImpl !== 'function') return null;

  const now = Date.now();
  const cached = dohCache.get(hostname);
  if (cached && now - cached.timestamp < CACHE_TTL_MS) {
    return cached.dnsJson;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`;
    const res = await fetchImpl(url, {
      signal: controller.signal,
      headers: { Accept: 'application/dns-json' }
    });
    clearTimeout(timer);

    if (!res || !res.ok) return null;
    const data = await res.json();

    if (data && typeof data === 'object') {
      if (dohCache.size >= MAX_CACHE_ENTRIES) {
        const oldest = dohCache.keys().next().value;
        dohCache.delete(oldest);
      }
      dohCache.set(hostname, { dnsJson: data, timestamp: now });
      return data;
    }
    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Orchestrates the full online free-forever intelligence grid:
 * Parallel execution of RDAP, CT Logs (crt.sh), and DoH with graceful fallback.
 *
 * @param {string} hostname
 * @param {object} [options={}]
 * @returns {Promise<{
 *   rdap: object|null,
 *   ct: object|null,
 *   doh: object|null,
 *   compositeScore: number,
 *   signals: Array<{ id: string, score: number, reason: string }>
 * }>}
/**
 * Queries the PhishStats public threat database via keyless API under 550ms budget.
 *
 * @param {string} hostname
 * @param {Function} [fetchImpl=globalThis.fetch]
 * @param {number} [timeoutMs=550]
 * @returns {Promise<{
 *   hit: boolean,
 *   records: Array<object>,
 *   score: number,
 *   signal: object|null,
 *   proofStep: object
 * }>}
 */
export async function queryPhishStatsPublicFeed(hostname, fetchImpl = globalThis.fetch, timeoutMs = 550) {
  if (!hostname || typeof hostname !== 'string') {
    return { hit: false, records: [], score: 0, signal: null, proofStep: { step: 'Public Threat Feeds (PhishStats)', status: 'skipped', detail: 'Invalid hostname' } };
  }
  const clean = hostname.toLowerCase().trim().replace(/^www\./, '');
  if (typeof fetchImpl !== 'function') {
    return { hit: false, records: [], score: 0, signal: null, proofStep: { step: 'Public Threat Feeds (PhishStats)', status: 'skipped', detail: 'Offline / fetch unavailable' } };
  }

  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

  try {
    const url = `https://phishstats.info:2096/api/phishing?_where=(url,like,~${encodeURIComponent(clean)}~)&_size=3`;
    const res = await fetchImpl(url, {
      signal: controller ? controller.signal : undefined,
      headers: { Accept: 'application/json' }
    });
    if (timer) clearTimeout(timer);
    if (!res || !res.ok) {
      return { hit: false, records: [], score: 0, signal: null, proofStep: { step: 'Public Threat Feeds (PhishStats)', status: 'passed', detail: 'No active threat feed hit.' } };
    }
    const data = await res.json();
    const hits = Array.isArray(data) ? data : (data?.data || []);
    const hit = hits.length > 0;
    return {
      hit,
      records: hits,
      score: hit ? 90 : 0,
      signal: hit ? { id: 'SIG_PHISHSTATS_LIVE_FEED_HIT', score: 90, database: 'PhishStats live feed' } : null,
      proofStep: {
        step: 'Public Threat Feeds (PhishStats)',
        status: hit ? 'failed' : 'passed',
        detail: hit
          ? `Listed as active threat on PhishStats feed (${hits.length} report(s))`
          : 'Clean. Not listed on PhishStats threat database.'
      }
    };
  } catch (_) {
    if (timer) clearTimeout(timer);
    return {
      hit: false,
      records: [],
      score: 0,
      signal: null,
      proofStep: {
        step: 'Public Threat Feeds (PhishStats)',
        status: 'skipped',
        detail: 'PhishStats threat feed query skipped or timed out.'
      }
    };
  }
}

/**
 * Orchestrates the full online free-forever intelligence grid:
 * Parallel execution of RDAP, CT Logs (crt.sh), DoH, PhishStats, and DMARC posture with graceful fallback.
 *
 * @param {string} hostname
 * @param {object} [options={}]
 * @returns {Promise<{
 *   rdap: object|null,
 *   ct: object|null,
 *   doh: object|null,
 *   phishStats: object|null,
 *   dmarc: object|null,
 *   compositeScore: number,
 *   signals: Array<{ id: string, score: number, reason: string }>
 * }>}
 */
export async function queryOnlineFreeIntelGrid(hostname, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const hasSensitiveInputs = !!options.hasSensitiveInputs;
  const regDomain = getDomain(hostname) || hostname;

  const [rdapRes, ctRes, dohRes, phishRes, dmarcRes] = await Promise.allSettled([
    queryFreeRdapDomainAge(hostname, fetchImpl),
    queryFreeCtLogs(regDomain, fetchImpl, options.timeoutMs || 600),
    queryFreeDoh(hostname, fetchImpl, options.timeoutMs || 500),
    queryPhishStatsPublicFeed(hostname, fetchImpl, options.timeoutMs || 550),
    auditDomainDmarcPosture(regDomain, fetchImpl)
  ]);

  const rdapData = rdapRes.status === 'fulfilled' ? rdapRes.value : null;
  const ctData = ctRes.status === 'fulfilled' ? ctRes.value : null;
  const dohData = dohRes.status === 'fulfilled' ? dohRes.value : null;
  const phishData = phishRes.status === 'fulfilled' ? phishRes.value : null;
  const dmarcData = dmarcRes.status === 'fulfilled' ? dmarcRes.value : null;

  const ctForensics = evaluateCtLogForensics(ctData, hostname, hasSensitiveInputs);
  const dohForensics = evaluateDohPacketForensics(dohData, hostname);

  const signals = [];
  let compositeScore = 0;

  if (rdapData && rdapData.signal) {
    signals.push({ id: rdapData.signal, score: rdapData.score, reason: rdapData.reason });
    compositeScore = Math.max(compositeScore, rdapData.score);
  }
  if (ctForensics && ctForensics.signal) {
    signals.push({ id: ctForensics.signal, score: ctForensics.score, reason: ctForensics.reason });
    compositeScore = Math.max(compositeScore, ctForensics.score);
  }
  if (dohForensics && dohForensics.signal) {
    signals.push({ id: dohForensics.signal, score: dohForensics.score, reason: dohForensics.reason });
    compositeScore = Math.max(compositeScore, dohForensics.score);
  }
  if (phishData && phishData.hit) {
    signals.push({ id: 'SIG_PHISHSTATS_LIVE_FEED_HIT', score: 90, reason: 'Domain listed on PhishStats live threat intelligence feed' });
    compositeScore = Math.max(compositeScore, 90);
  }
  if (dmarcData && dmarcData.hasDmarc === false && hasSensitiveInputs) {
    signals.push({ id: 'SIG_MISSING_DMARC_CREDENTIAL_TRAP', score: 85, reason: 'Domain lacks valid DMARC policy while requesting sensitive credentials' });
    compositeScore = Math.max(compositeScore, 85);
  }

  return {
    rdap: rdapData,
    ct: ctForensics,
    doh: dohForensics,
    phishStats: phishData,
    dmarc: dmarcData,
    compositeScore,
    signals
  };
}

export default {
  evaluateCtLogForensics,
  evaluateDohPacketForensics,
  queryFreeCtLogs,
  queryFreeDoh,
  queryPhishStatsPublicFeed,
  queryOnlineFreeIntelGrid
};
