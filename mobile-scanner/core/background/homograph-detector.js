/**
 * homograph-detector.js — Unicode Confusable & Homograph Attack Detection
 *
 * Protects users from internationalized domain name (IDN) homograph attacks,
 * mixed-script spoofing, and lookalike character brand impersonation
 * (e.g., Cyrillic 'а' replacing Latin 'a' in 'apple.com' -> xn--pple-43d.com).
 */

import { getDomain, getPublicSuffix } from '../shared/psl.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { t } from '../shared/messages.js';

// ─── Unicode Confusable Mapping Table ───────────────────────────────────────
// Maps visually identical or deceptive non-Latin characters to Latin ASCII equivalents
const CONFUSABLE_MAP = {
  // Cyrillic Lowercase
  '\u0430': 'a', // Cyrillic Small Letter A
  '\u0431': 'b', // Cyrillic Small Letter Be
  '\u0432': 'v', // Cyrillic Small Letter Ve
  '\u0433': 'r', // Cyrillic Small Letter Ghe
  '\u0434': 'd', // Cyrillic Small Letter De
  '\u0435': 'e', // Cyrillic Small Letter Ie
  '\u0451': 'e', // Cyrillic Small Letter Io
  '\u0436': 'zh',
  '\u0437': 'z',
  '\u0438': 'u', // Cyrillic Small Letter I (looks like reversed N, often confused with u)
  '\u0439': 'u',
  '\u043A': 'k', // Cyrillic Small Letter Ka
  '\u043B': 'l', // Cyrillic Small Letter El
  '\u043C': 'm', // Cyrillic Small Letter Em
  '\u043D': 'h', // Cyrillic Small Letter En (looks like Latin H)
  '\u043E': 'o', // Cyrillic Small Letter O
  '\u043F': 'n', // Cyrillic Small Letter Pe (looks like Latin n/pi)
  '\u0440': 'p', // Cyrillic Small Letter Er (looks like Latin p)
  '\u0441': 'c', // Cyrillic Small Letter Es (looks like Latin c)
  '\u0442': 't', // Cyrillic Small Letter Te
  '\u0443': 'y', // Cyrillic Small Letter U (looks like Latin y)
  '\u0445': 'x', // Cyrillic Small Letter Ha (looks like Latin x)
  '\u0446': 'u',
  '\u0448': 'w',
  '\u044A': 'b',
  '\u044B': 'bl',
  '\u044C': 'b',
  '\u044D': 'e',
  '\u044E': 'u',
  '\u044F': 'r',
  '\u0455': 's', // Cyrillic Small Letter Dze (looks like Latin s)
  '\u0456': 'i', // Cyrillic Small Letter Byelorussian-Ukrainian I
  '\u0457': 'i', // Cyrillic Small Letter Yi
  '\u0458': 'j', // Cyrillic Small Letter Je (looks like Latin j)
  '\u0473': 'f',

  // Cyrillic Uppercase
  '\u0410': 'a', '\u0412': 'b', '\u0415': 'e', '\u041A': 'k',
  '\u041C': 'm', '\u041D': 'h', '\u041E': 'o', '\u0420': 'p',
  '\u0421': 'c', '\u0422': 't', '\u0423': 'y', '\u0425': 'x',
  '\u0405': 's', '\u0406': 'i', '\u0408': 'j',

  // Greek Lowercase & Uppercase
  '\u03B1': 'a', '\u0391': 'a', // Alpha
  '\u03B2': 'b', '\u0392': 'b', // Beta
  '\u03B5': 'e', '\u0395': 'e', // Epsilon
  '\u03B7': 'n', '\u0397': 'h', // Eta
  '\u03B9': 'i', '\u0399': 'i', // Iota
  '\u03BA': 'k', '\u039A': 'k', // Kappa
  '\u03BD': 'v', '\u039D': 'n', // Nu
  '\u03BF': 'o', '\u039F': 'o', // Omicron
  '\u03C1': 'p', '\u03A1': 'p', // Rho
  '\u03C3': 's', '\u03C2': 's', // Sigma
  '\u03C4': 't', '\u03A4': 't', // Tau
  '\u03C5': 'u', '\u03A5': 'y', // Upsilon
  '\u03C7': 'x', '\u03A7': 'x', // Chi
  '\u03C9': 'w', '\u03A9': 'w'  // Omega
};

/**
 * RFC 3492 Punycode digit decoding.
 */
function punycodeDigit(cp) {
  if (cp >= 48 && cp <= 57) return cp - 22; // '0'-'9' -> 26-35
  if (cp >= 97 && cp <= 122) return cp - 97; // 'a'-'z' -> 0-25
  return 36;
}

/**
 * RFC 3492 Bias adaptation.
 */
function adapt(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / 700) : Math.floor(delta / 2);
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((36 - 1) * 26) / 2) {
    delta = Math.floor(delta / (36 - 1));
    k += 36;
  }
  return Math.floor(k + ((36 - 1 + 1) * delta) / (delta + 38));
}

/**
 * RFC 3492 Punycode decoder for a single label (e.g., 'xn--pple-43d' -> 'аpple').
 * @param {string} input - Label string
 * @returns {string} Decoded Unicode string
 */
export function decodePunycodeLabel(input) {
  if (!input || !input.startsWith('xn--')) return input;
  const str = input.slice(4).toLowerCase();
  const base = 36;
  const tmin = 1;
  const tmax = 26;
  const skew = 38;
  const initialBias = 72;
  const initialN = 128;
  const delimiter = '-';

  const output = [];
  let n = initialN;
  let i = 0;
  let bias = initialBias;

  const basicLength = str.lastIndexOf(delimiter);
  if (basicLength > 0) {
    for (let j = 0; j < basicLength; ++j) {
      output.push(String.fromCharCode(str.charCodeAt(j)));
    }
  }

  let inIndex = basicLength > 0 ? basicLength + 1 : 0;
  while (inIndex < str.length) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (inIndex >= str.length) break;
      const digit = punycodeDigit(str.charCodeAt(inIndex++));
      i += digit * w;
      const t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
      if (digit < t) break;
      w *= (base - t);
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= (output.length + 1);
    output.splice(i, 0, String.fromCodePoint(n));
    i++;
  }
  return output.join('');
}

/**
 * Decodes all punycode labels in a hostname.
 * E.g. 'xn--pple-43d.com' -> 'аpple.com'
 * @param {string} hostname
 * @returns {string}
 */
export function decodePunycodeHostname(hostname) {
  if (!hostname || !hostname.includes('xn--')) return hostname || '';
  return hostname
    .split('.')
    .map(label => decodePunycodeLabel(label))
    .join('.');
}

/**
 * Normalizes Unicode confusables, accents, and punycode to standard Latin ASCII.
 * E.g. 'xn--pple-43d.com' -> 'apple.com'
 * E.g. 'pаypal.com' (Cyrillic а) -> 'paypal.com'
 * @param {string} str
 * @returns {string} Normalized ASCII string
 */
export function normalizeConfusables(str) {
  if (!str) return '';
  // 1. Decode any Punycode labels
  let decoded = decodePunycodeHostname(str.toLowerCase());

  // 2. Normalize Unicode accents / diacritics via NFKD decomposition
  decoded = decoded.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');

  // 3. Map known Cyrillic, Greek, and other visually confusable characters to Latin
  let result = '';
  for (const ch of decoded) {
    if (CONFUSABLE_MAP[ch]) {
      result += CONFUSABLE_MAP[ch];
    } else {
      result += ch;
    }
  }

  // 4. Also handle common leetspeak substitutions in domains
  return result;
}

/**
 * Detects mixed-script attacks in a domain label.
 * Legitimate international domains are written uniformly in a single script.
 * Mixing Latin ASCII with Cyrillic or Greek in the SAME label is a signature homograph attack.
 * @param {string} label
 * @returns {boolean}
 */
export function isMixedScriptLabel(label) {
  if (!label) return false;
  const decoded = decodePunycodeLabel(label);

  const hasLatin = /[a-z0-9]/i.test(decoded);
  const hasCyrillic = /[\u0400-\u04FF]/.test(decoded);
  const hasGreek = /[\u0370-\u03FF]/.test(decoded);

  // Mixed scripts within one label: Latin + Cyrillic or Latin + Greek
  if (hasLatin && (hasCyrillic || hasGreek)) return true;
  if (hasCyrillic && hasGreek) return true;

  return false;
}

/**
 * Analyzes a URL for homograph attacks and Unicode character spoofing.
 * Correlates against protected brands in brands.json.
 *
 * @param {string} urlString
 * @param {Array} brandsList
 * @returns {Object} Structured verdict { id, params, score, reason, triggered }
 */
export function detectHomographAttack(urlString, brandsList = []) {
  try {
    const url = new URL(urlString);
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { id: null, params: {}, score: 0, reason: null, triggered: false };
    }

    const hostname = url.hostname.toLowerCase();
    if (isAllowlistedDomain(hostname)) {
      return { id: null, params: {}, score: 0, reason: null, triggered: false };
    }

    const hasPunycode = hostname.includes('xn--');
    const hasNonAscii = /[^\x00-\x7F]/.test(hostname);

    if (!hasPunycode && !hasNonAscii) {
      return { id: null, params: {}, score: 0, reason: null, triggered: false };
    }

    const labels = hostname.split('.');
    const decodedHostname = decodePunycodeHostname(hostname);
    const normalizedHostname = normalizeConfusables(hostname);

    // 1. Check for mixed-script spoofing in any label
    const mixedLabel = labels.find(l => isMixedScriptLabel(l));
    const isMixed = !!mixedLabel;

    // 2. Extract root domain name from normalized hostname
    const cleanNormalized = normalizedHostname.replace(/^www\./, '');
    const normalizedDomain = getDomain(cleanNormalized) || cleanNormalized;
    const suffix = getPublicSuffix(cleanNormalized);
    let normalizedCore = normalizedDomain;
    if (suffix && normalizedDomain.endsWith('.' + suffix)) {
      normalizedCore = normalizedDomain.slice(0, -(suffix.length + 1));
    }
    const cleanCore = normalizedCore.replace(/[^a-z0-9]/g, '');

    // 3. Match against protected brands list
    for (const brand of brandsList) {
      const brandName = brand.name.toLowerCase().replace(/\s+/g, '');
      const legitDomains = brand.domains || [];

      // If the actual domain is already the legitimate domain of this brand, it is safe
      if (legitDomains.some(d => hostname === d || hostname.endsWith('.' + d))) {
        return { id: null, params: {}, score: 0, reason: null, triggered: false };
      }

      // Check if normalized host matches brand name or any legitimate domain core
      const matchesBrandName = cleanCore === brandName || cleanCore.startsWith(brandName) || cleanCore.endsWith(brandName);
      const matchesBrandDomain = legitDomains.some(d => {
        const dCore = d.split('.')[0].replace(/[^a-z0-9]/g, '');
        return cleanCore === dCore;
      });

      if (matchesBrandName || matchesBrandDomain) {
        return {
          id: 'RULE_HOMOGRAPH_ATTACK',
          params: {
            brand: brand.name,
            target: hostname,
            decoded: decodedHostname
          },
          score: 85,
          reason: t('RULE_HOMOGRAPH_ATTACK', { brand: brand.name, target: hostname }),
          triggered: true
        };
      }
    }

    // 4. Even if brand didn't match directly, mixed-script in a domain label is an active exploit
    if (isMixed) {
      return {
        id: 'RULE_HOMOGRAPH_ATTACK',
        params: {
          brand: 'Domain',
          target: hostname,
          decoded: decodedHostname
        },
        score: 75,
        reason: t('RULE_HOMOGRAPH_ATTACK', { brand: 'Domain', target: hostname }),
        triggered: true
      };
    }

    // 5. Non-brand Punycode on unverified domain still represents high-risk IDN
    if (hasPunycode) {
      return {
        id: 'RULE_HOMOGRAPH_ATTACK',
        params: {
          brand: 'Unverified IDN',
          target: hostname,
          decoded: decodedHostname
        },
        score: 65,
        reason: t('RULE_HOMOGRAPH_ATTACK', { brand: 'Unverified IDN', target: hostname }),
        triggered: true
      };
    }
  } catch (_) {}

  return { id: null, params: {}, score: 0, reason: null, triggered: false };
}
