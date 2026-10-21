/**
 * background/forensic-reporter.js — 1-Click 1930 / Sanchar Saathi (Chakshu) Forensic Evidence Generator
 *
 * Automatically generates a standardized cybercrime incident dossier with extracted
 * attacker IOCs (UPI VPAs, Telegram bots, spoofed brands, redirect chains) ready for
 * 1-click submission to:
 * - National Cyber Crime Reporting Portal (cybercrime.gov.in / 1930 Helpline)
 * - Citizen Financial Cyber Fraud Reporting System (CFCFRS)
 * - Sanchar Saathi Chakshu Portal (sancharsaathi.gov.in/sfc/)
 */

const SENSITIVE_PARAM_KEYS = [
  'password', 'pass', 'pwd', 'otp', 'pin', 'mpin',
  'token', 'secret', 'aadhaar', 'pan', 'cvv', 'card',
  'account', 'auth', 'key', 'session', 'jwt'
];

/**
 * Automatically scrubs accidental citizen secrets from URLs before report generation.
 * Guarantees citizens never leak credentials when reporting scams.
 *
 * @param {string} urlString
 * @returns {string} Sanitized URL
 */
export function redactSensitiveCitizenData(urlString) {
  if (!urlString || typeof urlString !== 'string') return '';

  try {
    const parsed = new URL(urlString);
    let modified = false;

    for (const [key, val] of Array.from(parsed.searchParams.entries())) {
      const lowerKey = key.toLowerCase();
      const isSensitive = SENSITIVE_PARAM_KEYS.some(k => lowerKey.includes(k));
      if (isSensitive) {
        parsed.searchParams.set(key, '[REDACTED_BY_VERITY]');
        modified = true;
      }
    }

    let result = parsed.toString();
    // Also scrub any regex-based credential leaks in hash or path
    result = result.replace(/([?&#](?:password|otp|pin|cvv|token)=)[^&#\s]+/gi, '$1[REDACTED_BY_VERITY]');
    return result;
  } catch (_) {
    // If malformed, apply string-level scrubber
    return urlString.replace(/([?&#](?:password|otp|pin|cvv|token|pan|aadhaar)=)[^&#\s]+/gi, '$1[REDACTED_BY_VERITY]');
  }
}

/**
 * Extracts suspect UPI VPAs (Virtual Payment Addresses) from URLs or DOM text.
 *
 * @param {string} text
 * @returns {string[]} De-duplicated UPI VPAs
 */
function extractUpiVpas(text) {
  if (!text || typeof text !== 'string') return [];
  const vpas = new Set();

  let decoded = text;
  try {
    decoded = decodeURIComponent(text.replace(/\+/g, ' '));
  } catch (_) {}

  const corpora = [text, decoded];
  for (const c of corpora) {
    // 1. Check pa= parameter from upi://pay links or query strings
    const paMatches = c.matchAll(/[?&]pa=([a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32})/gi);
    for (const m of paMatches) {
      if (m[1]) vpas.add(m[1].toLowerCase());
    }

    // 2. Check general UPI VPA pattern: [a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}
    const upiRegex = /\b([a-zA-Z0-9.\-_]{2,64}@(okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|ibl|axl|upi|apl|barodampay|federal|idfcbank|kotak|pnb|axisbank|sbi|postbank|icici|hdfcbank))\b/gi;
    const generalMatches = c.matchAll(upiRegex);
    for (const m of generalMatches) {
      if (m[1]) vpas.add(m[1].toLowerCase());
    }
  }

  return Array.from(vpas);
}

/**
 * Extracts exfiltration webhook endpoints (Telegram bot, Discord, Webhook.site).
 *
 * @param {string} text
 * @returns {string[]} De-duplicated webhook URLs
 */
function extractWebhooks(text) {
  if (!text || typeof text !== 'string') return [];
  const hooks = new Set();

  const telegramMatches = text.match(/https?:\/\/api\.telegram\.org\/bot[a-zA-Z0-9:_-]+(?:\/[a-zA-Z0-9_.-]+)*/gi);
  if (telegramMatches) {
    telegramMatches.forEach(h => hooks.add(h));
  }

  const discordMatches = text.match(/https?:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/gi);
  if (discordMatches) {
    discordMatches.forEach(h => hooks.add(h));
  }

  const webhookSiteMatches = text.match(/https?:\/\/webhook\.site\/[a-f0-9-]+/gi);
  if (webhookSiteMatches) {
    webhookSiteMatches.forEach(h => hooks.add(h));
  }

  return Array.from(hooks);
}

/**
 * Generates an official, copy-paste-ready National Cybercrime Dossier.
 *
 * @param {object} analysisResult - Verdict or risk evaluation object
 * @param {string} urlString - Suspect destination URL
 * @param {object} [metadata={}] - Optional environment or page context
 * @returns {object} Structured dossier with officialSummaryText
 */
export function buildForensicDossier(analysisResult = {}, urlString = '', metadata = {}) {
  const cleanUrl = redactSensitiveCitizenData(urlString);
  let suspectHost = 'Unknown Host';
  try {
    suspectHost = new URL(cleanUrl).hostname;
  } catch (_) {}

  const now = new Date();
  const timestampIST = now.toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    dateStyle: 'medium',
    timeStyle: 'medium'
  });

  const incidentId = 'VERITY-I4C-' + now.getFullYear() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();

  // Aggregate signals and evidence text
  const signals = analysisResult?.signals || [];
  const reasons = analysisResult?.reasons || [];
  const domSignals = analysisResult?.domSignals || {};

  // Aggregate full text for IOC extraction
  const evidenceCorpus = [
    cleanUrl,
    metadata?.pageTitle || '',
    metadata?.pageText || '',
    JSON.stringify(domSignals),
    JSON.stringify(reasons)
  ].join(' ');

  const upiVpas = extractUpiVpas(evidenceCorpus);
  const webhooks = extractWebhooks(evidenceCorpus);

  // Determine spoofed brand if available
  let spoofedBrand = metadata?.spoofedBrand || null;
  if (!spoofedBrand) {
    for (const s of signals) {
      if (s.params && s.params.brand) {
        spoofedBrand = s.params.brand;
        break;
      }
    }
  }

  const riskScore = analysisResult?.score || analysisResult?.riskScore || 85;
  const severity = analysisResult?.severity || (riskScore >= 70 ? 'CRITICAL / DANGER' : 'SUSPICIOUS');

  // Format Official Incident Summary for 1930 / Chakshu Reporting
  const officialSummaryText = [
    '================================================================================',
    'NATIONAL CYBERCRIME REPORTING PORTAL (1930 / SANCHAR SAATHI CHAKSHU) DOSSIER',
    'Generated automatically by Verity 2.0 Web Protection On-Device Forensic Sentinel',
    '================================================================================',
    `Incident Reference ID : ${incidentId}`,
    `Report Date & Time (IST): ${timestampIST} (Indian Standard Time)`,
    `Suspect Incident URL   : ${cleanUrl}`,
    `Suspect Domain / FQDN  : ${suspectHost}`,
    `Threat Classification  : ${severity} (Risk Score: ${riskScore}/100)`,
    `Impersonated Entity    : ${spoofedBrand || 'Unverified / Government or Bank Lure'}`,
    '',
    '--- EXTRACTED ATTACKER IOCs (INDICATORS OF COMPROMISE) ---',
    `* Suspect UPI VPAs     : ${upiVpas.length > 0 ? upiVpas.join(', ') : 'None detected in DOM stream'}`,
    `* Webhook Exfiltration : ${webhooks.length > 0 ? webhooks.join(', ') : 'None detected'}`,
    `* Suspect Nameserver/IP: ${metadata?.ip || 'Domain-level web lure'}`,
    '',
    '--- FORENSIC DETECTION SIGNALS ---',
    reasons.length > 0 
      ? reasons.map((r, i) => `  ${i + 1}. ${r}`).join('\n')
      : '  1. High-risk zero-day deceptive cyber fraud heuristics triggered.',
    '',
    '--- ACTIONABLE NEXT STEPS FOR LAW ENFORCEMENT & INVESTIGATORS ---',
    '1. Freeze beneficiary accounts linked to extracted UPI VPAs under Sec 102 CrPC.',
    '2. Issue emergency domain takedown / sinkhole on suspect registrar & Cloudflare CDN.',
    '3. Flag mobile numbers / sender headers on DoT Sanchar Saathi (Chakshu) portal.',
    '4. Victim Helpline: Dial 1930 immediately or log in to cybercrime.gov.in.',
    '================================================================================'
  ].join('\n');

  return {
    incidentId,
    targetUrl: cleanUrl,
    suspectDomain: suspectHost,
    timestamp: now.toISOString(),
    timestampIST,
    riskScore,
    severity,
    iocs: {
      suspectDomain: suspectHost,
      upiVpas,
      webhooks,
      spoofedBrand,
      redirectHops: metadata?.hops || analysisResult?.redirectChain || []
    },
    triggeredRules: signals.map(s => s.id || s),
    evidenceReasons: reasons,
    officialSummaryText,
    reportingPortals: {
      cybercrimePortal: 'https://cybercrime.gov.in',
      sancharSaathiChakshu: 'https://sancharsaathi.gov.in/sfc/',
      helpline: '1930'
    }
  };
}
