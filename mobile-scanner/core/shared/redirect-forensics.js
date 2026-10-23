/**
 * shared/redirect-forensics.js — Pure, Deterministic Redirect Chain Forensics Analyzer
 *
 * Designed with zero browser extension APIs and zero DOM dependencies so it can run
 * identically in the background service worker, mobile PWA, and test runners.
 */

import { getDomain } from './psl.js';

const ROTATOR_TLDS = ['.xyz', '.top', '.click', '.sbs', '.cfd', '.icu', '.buzz', '.monster', '.live', '.fun', '.cam'];

/**
 * Pure, deterministic redirect chain forensics analyzer.
 * Inspects multi-hop velocity, TLD turbulence, rotator query footprints, and tab-under background swaps.
 *
 * @param {Array<{ url: string, timestamp?: number, isTabHidden?: boolean } | string>} chain
 * @returns {{
 *   hasRapidMultiHop: boolean,
 *   hasTldTurbulence: boolean,
 *   hasAdRotatorQuery: boolean,
 *   hasTabUnderSwap: boolean,
 *   uniqueRootDomains: number,
 *   distinctRootDomains: string[],
 *   elapsedMs: number,
 *   detected: boolean,
 *   signals: string[]
 * }}
 */
export function analyzeRedirectChainForensics(chain = []) {
  const normalizedHops = (Array.isArray(chain) ? chain : []).map((hop, idx) => {
    if (typeof hop === 'string') {
      return { url: hop, timestamp: Date.now() + idx * 10, isTabHidden: false };
    }
    return {
      url: hop?.url || '',
      timestamp: typeof hop?.timestamp === 'number' ? hop.timestamp : Date.now() + idx * 10,
      isTabHidden: !!hop?.isTabHidden
    };
  }).filter(h => !!h.url);

  if (normalizedHops.length === 0) {
    return {
      hasRapidMultiHop: false,
      hasTldTurbulence: false,
      hasAdRotatorQuery: false,
      hasTabUnderSwap: false,
      uniqueRootDomains: 0,
      distinctRootDomains: [],
      elapsedMs: 0,
      detected: false,
      signals: []
    };
  }

  const getHopHostname = (urlStr) => {
    try {
      return new URL(urlStr).hostname.toLowerCase();
    } catch (_) {
      return '';
    }
  };

  const getHopRootDomain = (urlStr) => {
    const host = getHopHostname(urlStr);
    if (!host) return '';
    try {
      return getDomain(host) || host;
    } catch (_) {
      return host;
    }
  };

  const allRootDomains = new Set(normalizedHops.map(h => getHopRootDomain(h.url)).filter(Boolean));
  let elapsedMs = 0;
  if (normalizedHops.length >= 2) {
    elapsedMs = Math.max(0, normalizedHops[normalizedHops.length - 1].timestamp - normalizedHops[0].timestamp);
  }

  // 1. Multi-Hop Velocity (hasRapidMultiHop): >= 3 distinct root domains within 2500ms
  let hasRapidMultiHop = false;
  for (let i = 0; i < normalizedHops.length; i++) {
    const windowDomains = new Set();
    const d0 = getHopRootDomain(normalizedHops[i].url);
    if (d0) windowDomains.add(d0);
    for (let j = i + 1; j < normalizedHops.length; j++) {
      const dj = getHopRootDomain(normalizedHops[j].url);
      if (dj) windowDomains.add(dj);
      const diffMs = Math.max(0, normalizedHops[j].timestamp - normalizedHops[i].timestamp);
      if (windowDomains.size >= 3 && diffMs <= 2500) {
        hasRapidMultiHop = true;
        break;
      }
    }
    if (hasRapidMultiHop) break;
  }
  if (!hasRapidMultiHop && allRootDomains.size >= 3 && elapsedMs <= 2500) {
    hasRapidMultiHop = true;
  }

  // 2. TLD Reputation Turbulence (hasTldTurbulence): hops into high-risk rotator TLDs
  // (.xyz, .top, .click, .sbs, .cfd, .icu, .buzz, .monster, .live, .fun, .cam) from a different origin
  let hasTldTurbulence = false;
  for (let i = 1; i < normalizedHops.length; i++) {
    const prevHost = getHopHostname(normalizedHops[i - 1].url);
    const currHost = getHopHostname(normalizedHops[i].url);
    const prevRoot = getHopRootDomain(normalizedHops[i - 1].url);
    const currRoot = getHopRootDomain(normalizedHops[i].url);
    const isDifferent = (prevHost !== currHost) || (prevRoot !== currRoot);
    const isRotatorTld = ROTATOR_TLDS.some(tld => currHost.endsWith(tld));
    if (isDifferent && isRotatorTld) {
      hasTldTurbulence = true;
      break;
    }
  }

  // 3. Rotator Query Fingerprint (hasAdRotatorQuery): typical malvertising bridge parameters
  // (clickid=, subid=, zoneid=, aff_id=, campaign_id=, popunder=, or hex payloads > 64 chars) across intermediate hops
  const checkUrlForRotatorQuery = (urlStr) => {
    if (!urlStr) return false;
    const lower = urlStr.toLowerCase();
    const hasParam = ['clickid=', 'subid=', 'zoneid=', 'aff_id=', 'campaign_id=', 'popunder='].some(p => lower.includes(p));
    if (hasParam) return true;
    try {
      const u = new URL(urlStr);
      if (/[a-f0-9]{65,}/i.test(u.search) || /[a-f0-9]{65,}/i.test(u.pathname)) {
        return true;
      }
    } catch (_) {
      if (/[a-f0-9]{65,}/i.test(urlStr)) return true;
    }
    return false;
  };

  let hasAdRotatorQuery = false;
  for (let i = 0; i < normalizedHops.length - 1; i++) {
    if (checkUrlForRotatorQuery(normalizedHops[i].url)) {
      hasAdRotatorQuery = true;
      break;
    }
  }
  if (!hasAdRotatorQuery && normalizedHops.length > 2) {
    for (let i = 1; i < normalizedHops.length - 1; i++) {
      if (checkUrlForRotatorQuery(normalizedHops[i].url)) {
        hasAdRotatorQuery = true;
        break;
      }
    }
  }

  // 4. Tab-Under Background Swap (hasTabUnderSwap): redirect occurs in background/hidden tab
  // (isTabHidden: true) to a different domain shortly after popup/new-tab spawn
  let hasTabUnderSwap = false;
  for (let i = 1; i < normalizedHops.length; i++) {
    if (normalizedHops[i].isTabHidden) {
      const prevRoot = getHopRootDomain(normalizedHops[0].url) || getHopHostname(normalizedHops[0].url);
      const currRoot = getHopRootDomain(normalizedHops[i].url) || getHopHostname(normalizedHops[i].url);
      if (prevRoot && currRoot && prevRoot !== currRoot) {
        hasTabUnderSwap = true;
        break;
      }
    }
  }
  if (!hasTabUnderSwap) {
    const hiddenHop = normalizedHops.find((h, idx) => idx > 0 && h.isTabHidden);
    if (hiddenHop) {
      const originRoot = getHopRootDomain(normalizedHops[0].url);
      const targetRoot = getHopRootDomain(hiddenHop.url);
      if (originRoot && targetRoot && originRoot !== targetRoot) {
        hasTabUnderSwap = true;
      }
    }
  }

  const signals = [];
  if (hasRapidMultiHop && (hasTldTurbulence || hasAdRotatorQuery)) {
    signals.push('SIG_MALVERTISING_REDIRECT_CHAIN');
  }
  if (hasTabUnderSwap) {
    signals.push('SIG_TAB_UNDER_HIJACK');
  }

  return {
    hasRapidMultiHop,
    hasTldTurbulence,
    hasAdRotatorQuery,
    hasTabUnderSwap,
    uniqueRootDomains: allRootDomains.size,
    distinctRootDomains: Array.from(allRootDomains),
    elapsedMs,
    detected: signals.length > 0,
    signals
  };
}

export default {
  analyzeRedirectChainForensics
};
