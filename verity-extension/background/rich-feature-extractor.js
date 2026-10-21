/**
 * rich-feature-extractor.js — Rich lexical URL feature extractor for ML inference.
 * Mathematically identical to training/retrain_model.py for parity.
 */

const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.site', '.online', '.info',
  '.monster', '.click', '.sbs', '.cfd', '.rest', '.icu', '.cyou',
  '.buzz', '.lat', '.skin', '.hair', '.boats', '.quest', '.shop',
  '.live', '.fun'
]);

const KEYWORDS = [
  'login', 'verify', 'secure', 'account', 'banking', 'update',
  'signin', 'wallet', 'claim', 'otp', 'support', 'auth', 'bill'
];

export function calculateEntropy(text) {
  if (!text || text.length === 0) return 0.0;
  const len = text.length;
  const freq = {};
  for (let i = 0; i < len; i++) {
    const c = text[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  let ent = 0.0;
  for (const c in freq) {
    const p = freq[c] / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

export function extractRichFeatures(urlString) {
  let url = urlString;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }

  let hostname = '';
  let pathname = '';
  let search = '';
  try {
    const parsed = new URL(url);
    hostname = (parsed.hostname || '').toLowerCase();
    pathname = parsed.pathname || '';
    search = parsed.search || '';
  } catch (e) {
    hostname = '';
  }

  // 1. Lengths
  const urlLen = url.length;
  const hostLen = hostname.length;
  const pathLen = pathname.length;

  // 2. Digit ratios
  let digits = 0;
  for (let i = 0; i < urlLen; i++) {
    const code = url.charCodeAt(i);
    if (code >= 48 && code <= 57) digits++;
  }
  const digitRatio = digits / Math.max(urlLen, 1);

  let hostDigits = 0;
  for (let i = 0; i < hostLen; i++) {
    const code = hostname.charCodeAt(i);
    if (code >= 48 && code <= 57) hostDigits++;
  }
  const hostDigitRatio = hostDigits / Math.max(hostLen, 1);

  // 3. Host Entropy
  const hostEntropy = calculateEntropy(hostname);

  // 4. Special character counts
  const dotCount = (url.match(/\./g) || []).length;
  const hyphenCount = (url.match(/-/g) || []).length;
  const atCount = (url.match(/@/g) || []).length;
  const slashCount = (url.match(/\//g) || []).length;
  const queryCount = (url.match(/\?/g) || []).length;
  const equalCount = (url.match(/=/g) || []).length;

  // 5. Host token count (split by . and -)
  const hostTokens = hostname.split(/[\.-]/).length;

  // 6. Structural flags
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const isIp = ipv4Regex.test(hostname) ? 1.0 : 0.0;
  const isHttps = url.startsWith('https://') ? 1.0 : 0.0;

  const lastDoubleSlash = url.lastIndexOf('//');
  const doubleSlash = (lastDoubleSlash > 7) ? 1.0 : 0.0;

  // 7. Suspicious TLD & Keywords
  let isSuspiciousTld = 0.0;
  for (const tld of SUSPICIOUS_TLDS) {
    if (hostname.endsWith(tld)) {
      isSuspiciousTld = 1.0;
      break;
    }
  }

  const urlLower = url.toLowerCase();
  let keywordMatches = 0.0;
  for (const kw of KEYWORDS) {
    if (urlLower.includes(kw)) keywordMatches++;
  }

  return [
    urlLen, hostLen, pathLen, digitRatio, hostDigitRatio,
    hostEntropy, dotCount, hyphenCount, atCount, slashCount,
    queryCount, equalCount, hostTokens, isIp, isHttps,
    doubleSlash, isSuspiciousTld, keywordMatches
  ];
}

function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Extracts 8 advanced structural & lexical signals to elevate detection
 * of evasion techniques, suspicious port anomalies, and directory depths.
 *
 * 19. vowel_consonant_ratio
 * 20. brand_min_distance
 * 21. has_idn_mixed_script
 * 22. num_subdomain_levels
 * 23. sensitive_dir_depth
 * 24. longest_token_len
 * 25. special_char_density
 * 26. is_port_in_url
 *
 * @param {string} urlString
 * @param {Array} [brandsList]
 * @returns {number[]} Array of 8 advanced feature values
 */
export function extractAdvancedFeatures(urlString, brandsList = []) {
  let url = urlString;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }

  let parsed = null;
  let hostname = '';
  let pathname = '';
  let port = '';
  try {
    parsed = new URL(url);
    hostname = (parsed.hostname || '').toLowerCase();
    pathname = (parsed.pathname || '').toLowerCase();
    port = parsed.port || '';
  } catch (_) {
    hostname = '';
  }

  // 19. Vowel-to-consonant ratio
  const vowels = (hostname.match(/[aeiou]/g) || []).length;
  const consonants = (hostname.match(/[bcdfghjklmnpqrstvwxyz]/g) || []).length;
  const vowelConsonantRatio = vowels / Math.max(consonants + 1, 1);

  // 20. Brand minimum distance
  let minBrandDist = 99;
  if (Array.isArray(brandsList) && brandsList.length > 0) {
    const hostParts = hostname.split('.');
    const baseHost = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : hostname;
    for (const b of brandsList) {
      const bName = typeof b === 'string' ? b.toLowerCase() : (b?.name || '').toLowerCase();
      if (!bName) continue;
      if (Math.abs(baseHost.length - bName.length) > 3) continue;
      const d = levenshteinDistance(baseHost, bName);
      if (d < minBrandDist) minBrandDist = d;
    }
  }
  const brandMinDistance = minBrandDist === 99 ? 10.0 : Math.min(minBrandDist, 10.0);

  // 21. Has IDN mixed script (Latin mixed with Cyrillic/Greek)
  const hasMixedScript = (/[\u0400-\u04FF\u0370-\u03FF]/.test(hostname) && /[a-z]/.test(hostname)) ? 1.0 : 0.0;

  // 22. Subdomain levels
  const hostDots = (hostname.match(/\./g) || []).length;
  const numSubdomainLevels = Math.max(0, hostDots - 1);

  // 23. Sensitive directory depth
  const sensitiveKeywords = ['wp-content', 'wp-includes', 'plugins', 'assets', 'admin', 'login', 'auth', 'signin'];
  let sensitiveDirDepth = 0.0;
  for (const kw of sensitiveKeywords) {
    if (pathname.includes(kw)) sensitiveDirDepth++;
  }

  // 24. Longest alphabetic token length in hostname
  const tokens = hostname.split(/[^a-zA-Z]/).filter(Boolean);
  let longestTokenLen = 0;
  for (const t of tokens) {
    if (t.length > longestTokenLen) longestTokenLen = t.length;
  }

  // 25. Special character density
  const specialChars = (url.match(/[_~%=&]/g) || []).length;
  const specialCharDensity = specialChars / Math.max(url.length, 1);

  // 26. Non-standard port flag
  const isPortInUrl = (port && !['80', '443', ''].includes(port)) ? 1.0 : 0.0;

  return [
    vowelConsonantRatio,
    brandMinDistance,
    hasMixedScript,
    numSubdomainLevels,
    sensitiveDirDepth,
    longestTokenLen,
    specialCharDensity,
    isPortInUrl
  ];
}

/**
 * Combines 18 baseline rich lexical features with 8 advanced structural features
 * to produce the full 26-feature vector for next-generation quantized model inference.
 *
 * @param {string} urlString
 * @param {Array} [brandsList]
 * @returns {number[]} 26-element float array
 */
export function extract26Features(urlString, brandsList = []) {
  const base18 = extractRichFeatures(urlString);
  const adv8 = extractAdvancedFeatures(urlString, brandsList);
  return base18.concat(adv8);
}
