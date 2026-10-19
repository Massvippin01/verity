/**
 * domain-age.js — RDAP-based Newly Registered Domain (NRD) Detection
 *
 * Ephemeral/disposable domains registered within the last 14-30 days are
 * heavily correlated with active phishing, malvertising, and cyber fraud campaigns.
 *
 * Queries authoritative ICANN/IANA RDAP servers (RFC 7480-7484), caches results
 * in-memory and local storage with a 7-day TTL, and fails safely without blocking.
 */

import { getDomain } from '../shared/psl.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { isTrustedTopDomain } from './rules.js';
import { t } from '../shared/messages.js';

// Cache: domain -> { ageDays: number, checkedAt: number }
const domainAgeCache = new Map();
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Get RDAP URL for a given domain based on TLD.
 */
function getRdapUrl(domain) {
  const parts = domain.toLowerCase().split('.');
  const tld = parts[parts.length - 1];

  switch (tld) {
    case 'com':
      return `https://rdap.verisign.com/com/v1/domain/${domain}`;
    case 'net':
      return `https://rdap.verisign.com/net/v1/domain/${domain}`;
    case 'org':
      return `https://rdap.publicinterestregistry.org/rdap/domain/${domain}`;
    default:
      return `https://rdap.iana.org/domain/${domain}`;
  }
}

/**
 * Extract registration date from standard RDAP events array.
 */
function extractRegistrationDate(events) {
  if (!Array.isArray(events)) return null;
  const regEvent = events.find(e => e && (e.eventAction === 'registration' || e.eventAction === 'created'));
  return regEvent ? regEvent.eventDate : null;
}

/**
 * Check the registration age of a domain via RDAP.
 *
 * @param {string} urlString
 * @returns {Promise<{ id: string|null, params: object, score: number, reason: string|null, triggered: boolean }>}
 */
export async function checkDomainAge(urlString) {
  const empty = { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!urlString) return empty;

  let hostname = '';
  try {
    hostname = new URL(urlString).hostname.toLowerCase();
  } catch (_) {
    return empty;
  }

  // 1. Allowlisted & trusted top domains are never queried
  if (isAllowlistedDomain(hostname) || isTrustedTopDomain(hostname)) {
    return empty;
  }

  // 2. Extract registered domain
  const domain = getDomain(hostname);
  if (!domain || !domain.includes('.')) {
    return empty; // IP host or invalid domain
  }

  // 3. Check memory cache
  const cached = domainAgeCache.get(domain);
  if (cached && (Date.now() - cached.checkedAt) < CACHE_TTL_MS) {
    return formatAgeVerdict(domain, cached.ageDays);
  }

  // 4. Query RDAP server with strict timeout
  try {
    const rdapUrl = getRdapUrl(domain);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500); // 2.5s timeout

    const res = await fetch(rdapUrl, {
      headers: {
        'Accept': 'application/rdap+json, application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      const regDateStr = extractRegistrationDate(data.events);

      if (regDateStr) {
        const regTime = new Date(regDateStr).getTime();
        if (!isNaN(regTime)) {
          const ageDays = (Date.now() - regTime) / (1000 * 60 * 60 * 24);
          domainAgeCache.set(domain, { ageDays, checkedAt: Date.now() });
          return formatAgeVerdict(domain, ageDays);
        }
      }
    }
  } catch (_) {
    // Timeout, offline, or RDAP error — fail safe
  }

  return empty;
}

/**
 * Format domain age into risk verdict based on age in days.
 */
function formatAgeVerdict(domain, ageDays) {
  const rounded = Math.max(0, Math.round(ageDays));
  let score = 0;

  if (rounded < 7) {
    score = 40; // Brand new domain registered within the past week
  } else if (rounded < 30) {
    score = 25; // Registered within the past month
  } else if (rounded < 60) {
    score = 10; // Young domain
  }

  if (score > 0) {
    return {
      id: 'SIG_NEWLY_REGISTERED_DOMAIN',
      params: { ageDays: rounded, domain },
      score,
      reason: t('SIG_NEWLY_REGISTERED_DOMAIN', { ageDays: rounded }),
      triggered: true
    };
  }

  return { id: null, params: { ageDays: rounded, domain }, score: 0, reason: null, triggered: false };
}
