import { getDomain, getPublicSuffix } from '../shared/psl.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { t } from '../shared/messages.js';
import { normalizeConfusables } from './homograph-detector.js';

/**
 * Calculates the Levenshtein distance between two strings.
 * Used for detecting typosquatting (e.g., paypa1 vs paypal).
 */
function levenshteinDistance(a, b) {
  const matrix = [];
  
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) == a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, // substitution
                                Math.min(matrix[i][j - 1] + 1, // insertion
                                         matrix[i - 1][j] + 1)); // deletion
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Normalizes a hostname for brand comparison.
 * Decodes punycode/confusables, strips www. and the TLD if possible to compare the root word.
 */
function normalizeHostname(hostname) {
  const normalized = normalizeConfusables(hostname || '');
  const clean = normalized.toLowerCase().replace(/^www\./, '');
  const domain = getDomain(clean);
  if (domain) {
    const suffix = getPublicSuffix(clean);
    if (suffix && domain.endsWith('.' + suffix)) {
      return domain.slice(0, -(suffix.length + 1)).replace(/[^a-z0-9]/g, '');
    }
    return domain.replace(/[^a-z0-9]/g, '');
  }
  return clean.replace(/[^a-z0-9]/g, '');
}

/**
 * Analyzes a hostname against a list of protected brands using Edit Distance.
 * @param {string} urlString 
 * @param {Array} brandsList 
 * @returns {Object} score and reason if triggered
 */
export function detectTyposquatting(urlString, brandsList) {
  try {
    const url = new URL(urlString);
    if (!['http:', 'https:'].includes(url.protocol)) return { id: null, params: {}, score: 0, reason: null, triggered: false };

    const hostname = url.hostname.toLowerCase();
    if (isAllowlistedDomain(hostname)) {
      return { id: null, params: {}, score: 0, reason: null, triggered: false };
    }
    const normalizedHost = normalizeHostname(hostname);
    
    // First, verify if it's already a legitimate domain
    for (const brand of brandsList) {
      if (brand.domains.some(legit => hostname === legit || hostname.endsWith('.' + legit))) {
        return { id: null, params: {}, score: 0, reason: null, triggered: false }; // Legit site
      }
    }

    // Now check for typosquatting using precision constraints:
    // 1. Length delta guard: cannot insert or delete > 1 character
    // 2. Relative edit distance ratio <= 0.20 (requires >= 80% character identity)
    // 3. For short brands (len <= 4), forbid arbitrary single-letter substitutions
    for (const brand of brandsList) {
      const brandName = brand.name.toLowerCase().replace(/\s+/g, '');
      const cleanHost = normalizedHost.replace(/[^a-z0-9]/g, '');
      const cleanBrand = brandName.replace(/[^a-z0-9]/g, '');

      if (!cleanHost || !cleanBrand || cleanHost === cleanBrand) continue;

      const lenDiff = Math.abs(cleanHost.length - cleanBrand.length);
      if (lenDiff > 1) continue; // Length difference too large to be a typosquat

      const maxLen = Math.max(cleanHost.length, cleanBrand.length);
      const distance = levenshteinDistance(cleanHost, cleanBrand);
      if (distance === 0) continue;

      // Require at least 80% character identity (relative ratio <= 0.20)
      const relRatio = distance / maxLen;
      if (relRatio > 0.20) continue;

      // For short brands (len <= 4), single-letter substitutions are almost always
      // independent dictionary words (e.g. fox vs Box, loom vs Zoom, viva vs Visa)
      if (cleanBrand.length <= 4 && cleanHost.length === cleanBrand.length) {
        continue;
      }

      return {
        id: 'BRAND_TYPOSQUATTING',
        params: { brand: brand.name, distance },
        score: 85,
        reason: t('BRAND_TYPOSQUATTING', { brand: brand.name, distance }),
        triggered: true
      };
    }
    
  } catch (e) {}
  
  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}

