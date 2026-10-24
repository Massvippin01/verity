/**
 * content/search-shield.js — Search Engine (SERP) Sponsored Ad & Link Pre-Scanner
 *
 * Pre-evaluates search engine result and sponsored ad links on Google, Bing, and DuckDuckGo
 * before the citizen clicks them, preventing malvertising redirection to fake customer support numbers,
 * trojanized utility software downloads (AnyDesk, VLC, 7-Zip), and spoofed banking portals.
 *
 * Modeled after Bitdefender TrafficLight SERP Protection.
 */

'use strict';

import { isTrustedTopDomain } from '../background/rules.js';

export const SERP_PROTECTED_BRANDS = [
  {
    name: 'State Bank of India',
    keywords: ['sbi', 'state bank of india', 'onlinesbi', 'sbi card', 'yono sbi'],
    officialDomains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'sbicard.com', 'sbiyono.sbi']
  },
  {
    name: 'HDFC Bank',
    keywords: ['hdfc', 'hdfc bank', 'hdfc netbanking', 'hdfc customer care'],
    officialDomains: ['hdfcbank.com', 'hdfc.com']
  },
  {
    name: 'ICICI Bank',
    keywords: ['icici', 'icici bank', 'icicibank', 'icici netbanking', 'icici helpline'],
    officialDomains: ['icicibank.com']
  },
  {
    name: 'AnyDesk',
    keywords: ['anydesk', 'any desk', 'download anydesk'],
    officialDomains: ['anydesk.com']
  },
  {
    name: 'VLC Media Player',
    keywords: ['vlc', 'vlc media player', 'videolan', 'download vlc'],
    officialDomains: ['videolan.org']
  },
  {
    name: '7-Zip',
    keywords: ['7-zip', '7zip', 'download 7-zip'],
    officialDomains: ['7-zip.org']
  },
  {
    name: 'OBS Studio',
    keywords: ['obs', 'obs studio', 'obsproject', 'download obs'],
    officialDomains: ['obsproject.com']
  },
  {
    name: 'Income Tax Department',
    keywords: ['income tax', 'incometax', 'itr e-filing', 'income tax portal'],
    officialDomains: ['incometax.gov.in', 'incometaxindia.gov.in', 'tin-nsdl.com']
  },
  {
    name: 'Passport Seva',
    keywords: ['passport seva', 'passport office', 'apply passport online', 'passport seva kendra'],
    officialDomains: ['passportindia.gov.in']
  },
  {
    name: 'Customer Support Helpline',
    keywords: ['customer care number', 'customer care helpline', 'toll free helpline', '24x7 support number', 'helpline number'],
    officialDomains: []
  }
];

export const SERP_SUSPICIOUS_TLDS = new Set([
  '.top', '.xyz', '.click', '.site', '.online', '.live', '.store', '.cc',
  '.tk', '.ml', '.ga', '.cf', '.gq', '.monster', '.icu', '.sbs', '.cfd',
  '.link', '.buzz', '.rest', '.shop', '.work', '.biz', '.download', '.fun'
]);

/**
 * Extracts and unwraps the real destination URL from search engine redirect bridges
 * (e.g., Google /aclk ad parameters, Google /url?q= redirects, or Bing /aclick).
 *
 * @param {string} rawHref
 * @returns {string} Unwrapped destination URL
 */
export function unwrapSearchDestinationUrl(rawHref) {
  if (!rawHref || typeof rawHref !== 'string') return '';
  const trimmed = rawHref.trim();

  try {
    const parsed = new URL(trimmed.startsWith('//') ? 'https:' + trimmed : trimmed);

    // Google Ad redirect (/aclk)
    if (parsed.pathname === '/aclk' || parsed.pathname.endsWith('/aclk')) {
      const adUrl = parsed.searchParams.get('adurl') || parsed.searchParams.get('q');
      if (adUrl) {
        return unwrapSearchDestinationUrl(adUrl);
      }
    }

    // Google Search redirect (/url?q=...)
    if (parsed.pathname === '/url') {
      const qUrl = parsed.searchParams.get('q') || parsed.searchParams.get('url');
      if (qUrl) {
        return unwrapSearchDestinationUrl(qUrl);
      }
    }

    // Bing Ad redirect (/aclick)
    if (parsed.pathname.includes('/aclick')) {
      const uUrl = parsed.searchParams.get('u');
      if (uUrl) {
        try {
          // Bing base64 or URL encodes target in 'u' param
          if (uUrl.startsWith('a1')) {
            const b64 = uUrl.slice(2).replace(/-/g, '+').replace(/_/g, '/');
            const decoded = atob(b64);
            if (decoded.startsWith('http://') || decoded.startsWith('https://')) {
              return decoded;
            }
          }
        } catch (_) {}
      }
    }

    return parsed.href;
  } catch (_) {
    return trimmed;
  }
}

/**
 * Evaluates a search result link or sponsored ad before the citizen clicks.
 *
 * @param {string} anchorHref - Destination or redirect URL
 * @param {string} [anchorTitleText=''] - Search snippet or ad heading text
 * @param {boolean} [isSponsoredAd=false] - Whether the result is marked as 'Sponsored' / 'Ad'
 * @returns {{
 *   status: 'safe' | 'caution' | 'danger',
 *   score: number,
 *   badgeText: string,
 *   signal: string|null,
 *   destinationUrl: string,
 *   destinationHost: string,
 *   matchedBrand: string|null,
 *   reason: string|null
 * }}
 */
export function evaluateSearchResultLink(anchorHref, anchorTitleText = '', isSponsoredAd = false) {
  const unwrappedUrl = unwrapSearchDestinationUrl(anchorHref);
  let destUrl;
  try {
    destUrl = new URL(unwrappedUrl);
  } catch (_) {
    return {
      status: 'safe',
      score: 0,
      badgeText: 'Unknown',
      signal: null,
      destinationUrl: anchorHref,
      destinationHost: '',
      matchedBrand: null,
      reason: null
    };
  }

  const destHost = destUrl.hostname.toLowerCase().replace(/^www\./, '');
  const titleLower = (anchorTitleText || '').toLowerCase();

  // Check TLD
  const hasSuspiciousTld = Array.from(SERP_SUSPICIOUS_TLDS).some(tld => destHost.endsWith(tld));

  // Match claimed brand in title/heading
  for (const brand of SERP_PROTECTED_BRANDS) {
    const matchesKeyword = brand.keywords.some(kw => {
      const regex = new RegExp(`(?:^|[^a-z0-9])${kw}(?:[^a-z0-9]|$)`, 'i');
      return regex.test(titleLower);
    });

    if (matchesKeyword) {
      // Check if destination is official
      const isOfficial = brand.officialDomains.some(d => destHost === d || destHost.endsWith('.' + d));

      if (isOfficial) {
        return {
          status: 'safe',
          score: 0,
          badgeText: 'Official',
          signal: null,
          destinationUrl: destUrl.href,
          destinationHost: destHost,
          matchedBrand: brand.name,
          reason: `Verified official domain for ${brand.name}`
        };
      }

      // If it's a generic helpline search result
      if (brand.officialDomains.length === 0) {
        if (isSponsoredAd || hasSuspiciousTld) {
          return {
            status: 'danger',
            score: 90,
            badgeText: 'Fake Helpline Ad',
            signal: 'SIG_SERP_SPONSORED_IMPERSONATION',
            destinationUrl: destUrl.href,
            destinationHost: destHost,
            matchedBrand: brand.name,
            reason: `Sponsored search ad advertising unverified customer care / helpline number on "${destHost}".`
          };
        }
        return {
          status: 'caution',
          score: 60,
          badgeText: 'Unverified Helpline',
          signal: 'SIG_SERP_SPONSORED_IMPERSONATION',
          destinationUrl: destUrl.href,
          destinationHost: destHost,
          matchedBrand: brand.name,
          reason: `Unverified customer care number link on third-party domain "${destHost}".`
        };
      }

      // Brand impersonation on unverified domain!
      if (isSponsoredAd || hasSuspiciousTld) {
        return {
          status: 'danger',
          score: 92,
          badgeText: isSponsoredAd ? 'Sponsored Scam Ad' : 'Malicious Impersonation',
          signal: 'SIG_SERP_SPONSORED_IMPERSONATION',
          destinationUrl: destUrl.href,
          destinationHost: destHost,
          matchedBrand: brand.name,
          reason: `Search ${isSponsoredAd ? 'Sponsored Ad' : 'result'} impersonating ${brand.name} routing to unofficial domain "${destHost}".`
        };
      }

      return {
        status: 'caution',
        score: 75,
        badgeText: 'Unverified Third-Party',
        signal: 'SIG_SERP_SPONSORED_IMPERSONATION',
        destinationUrl: destUrl.href,
        destinationHost: destHost,
        matchedBrand: brand.name,
        reason: `Search result claiming ${brand.name} hosted on unofficial domain "${destHost}".`
      };
    }
  }

  // No specific high-value brand claimed
  if (isSponsoredAd && hasSuspiciousTld) {
    return {
      status: 'caution',
      score: 55,
      badgeText: 'Suspicious Ad',
      signal: 'SIG_MALVERTISING',
      destinationUrl: destUrl.href,
      destinationHost: destHost,
      matchedBrand: null,
      reason: `Sponsored search ad routing to high-abuse TLD on "${destHost}".`
    };
  }

  return {
    status: 'safe',
    score: 0,
    badgeText: 'Search Result',
    signal: null,
    destinationUrl: destUrl.href,
    destinationHost: destHost,
    matchedBrand: null,
    reason: null
  };
}

export default {
  SERP_PROTECTED_BRANDS,
  SERP_SUSPICIOUS_TLDS,
  unwrapSearchDestinationUrl,
  evaluateSearchResultLink
};
