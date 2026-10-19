/**
 * favicon-matcher.js — Favicon MurmurHash3 Brand Fingerprinting
 *
 * Implements Shodan/Bitdefender-compatible 32-bit MurmurHash3 visual asset
 * fingerprinting. Phishing sites clone official favicons to achieve visual
 * fidelity. Matching the favicon hash against protected global brands reveals
 * zero-day phishing kits even on brand-new unindexed domains.
 */

import { getDomain } from '../shared/psl.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { isTrustedTopDomain } from './rules.js';
import { t } from '../shared/messages.js';

/**
 * Standard 32-bit MurmurHash3 implementation.
 * Compatible with Shodan http.favicon.hash calculation.
 * @param {string} str
 * @param {number} seed
 * @returns {number} 32-bit signed integer
 */
export function murmurHash3(str, seed = 0) {
  if (!str) return 0;
  let h1 = seed >>> 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  let i = 0;
  const len = str.length;

  while (i + 4 <= len) {
    let k1 = (str.charCodeAt(i) & 0xff) |
      ((str.charCodeAt(i + 1) & 0xff) << 8) |
      ((str.charCodeAt(i + 2) & 0xff) << 16) |
      ((str.charCodeAt(i + 3) & 0xff) << 24);
    i += 4;
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = (Math.imul(h1, 5) + 0xe6546b64) >>> 0;
  }

  let k1 = 0;
  const rem = len - i;
  if (rem === 3) k1 ^= (str.charCodeAt(i + 2) & 0xff) << 16;
  if (rem >= 2) k1 ^= (str.charCodeAt(i + 1) & 0xff) << 8;
  if (rem >= 1) {
    k1 ^= str.charCodeAt(i) & 0xff;
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return (h1 | 0);
}

/**
 * Catalog of known official brand favicon hashes (MurmurHash3 32-bit signed integer).
 * Matches Shodan internet intelligence dataset for top phished platforms.
 */
export const KNOWN_BRAND_FAVICONS = new Map([
  [1848946384, { name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'office.com'] }],
  [-1107577557, { name: 'PayPal', domains: ['paypal.com', 'paypalobjects.com'] }],
  [708578229, { name: 'Google', domains: ['google.com', 'google.co.in', 'gstatic.com'] }],
  [-1428383391, { name: 'Apple', domains: ['apple.com', 'icloud.com'] }],
  [1321459807, { name: 'Amazon', domains: ['amazon.com', 'amazon.in', 'media-amazon.com'] }],
  [-1245087797, { name: 'Netflix', domains: ['netflix.com', 'nflxext.com'] }],
  [-915648831, { name: 'Chase', domains: ['chase.com'] }],
  [1607598823, { name: 'Bank of America', domains: ['bankofamerica.com'] }],
  [-1338668472, { name: 'Wells Fargo', domains: ['wellsfargo.com'] }],
  [318287410, { name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'] }],
  [-1449833503, { name: 'Facebook', domains: ['facebook.com', 'meta.com'] }],
  [1812978330, { name: 'Telegram', domains: ['telegram.org'] }],
  [-1908862963, { name: 'Discord', domains: ['discord.com'] }]
]);

/**
 * Known official brand CDN favicon patterns.
 */
const BRAND_FAVICON_URL_PATTERNS = [
  { brand: 'Microsoft', pattern: /(microsoft\.com|live\.com|office\.com|s-microsoft\.com)\/.*favicon/i },
  { brand: 'PayPal', pattern: /(paypalobjects\.com|paypal\.com)\/.*favicon/i },
  { brand: 'Google', pattern: /(gstatic\.com|google\.com)\/.*favicon/i },
  { brand: 'Apple', pattern: /(apple\.com|icloud\.com)\/.*favicon/i },
  { brand: 'Netflix', pattern: /(nflxext\.com|netflix\.com)\/.*favicon/i },
  { brand: 'Amazon', pattern: /(amazon\.com|media-amazon\.com)\/.*favicon/i },
  { brand: 'Chase', pattern: /(chase\.com)\/.*favicon/i },
  { brand: 'Bank of America', pattern: /(bankofamerica\.com)\/.*favicon/i },
  { brand: 'Steam', pattern: /(steamcommunity\.com|steampowered\.com)\/.*favicon/i }
];

/**
 * Detects brand spoofing via Favicon MurmurHash3 or official CDN favicon hotlinking.
 *
 * @param {string} urlString
 * @param {object} domSignals
 * @param {Array} brandsList
 * @returns {object} Verdict { id, params, score, reason, triggered }
 */
export function detectFaviconSpoof(urlString, domSignals, brandsList = []) {
  const empty = { id: null, params: {}, score: 0, reason: null, triggered: false };
  if (!urlString || !domSignals) return empty;

  let hostname = '';
  try {
    hostname = new URL(urlString).hostname.toLowerCase();
  } catch (_) {
    return empty;
  }

  // Exempt allowlisted and trusted top domains
  if (isAllowlistedDomain(hostname) || isTrustedTopDomain(hostname)) {
    return empty;
  }

  const rootDomain = getDomain(hostname) || hostname;

  // 1. Direct Favicon MurmurHash3 Match
  if (domSignals.faviconHash !== undefined && domSignals.faviconHash !== null) {
    const hash = Number(domSignals.faviconHash);
    if (KNOWN_BRAND_FAVICONS.has(hash)) {
      const brandInfo = KNOWN_BRAND_FAVICONS.get(hash);
      const isLegit = (brandInfo.domains || []).some(d => hostname === d || hostname.endsWith('.' + d) || rootDomain === d);
      if (!isLegit) {
        return {
          id: 'SIG_FAVICON_BRAND_SPOOF',
          params: { brand: brandInfo.name, hash },
          score: 85,
          reason: t('SIG_FAVICON_BRAND_SPOOF', { brand: brandInfo.name }),
          triggered: true
        };
      }
    }
  }

  // 2. Official CDN Favicon URL Hotlinking
  const assetUrls = domSignals.brandAssetUrls || [];
  for (const assetUrl of assetUrls) {
    if (typeof assetUrl !== 'string') continue;
    for (const rule of BRAND_FAVICON_URL_PATTERNS) {
      if (rule.pattern.test(assetUrl)) {
        // Find brand domains in brandsList or default
        const brandObj = brandsList.find(b => b.name.toLowerCase() === rule.brand.toLowerCase());
        const legitDomains = brandObj ? brandObj.domains : [rule.brand.toLowerCase() + '.com'];
        const isLegit = legitDomains.some(d => hostname === d || hostname.endsWith('.' + d) || rootDomain === d);
        if (!isLegit) {
          return {
            id: 'SIG_FAVICON_BRAND_SPOOF',
            params: { brand: rule.brand, assetUrl },
            score: 85,
            reason: t('SIG_FAVICON_BRAND_SPOOF', { brand: rule.brand }),
            triggered: true
          };
        }
      }
    }
  }

  return empty;
}
