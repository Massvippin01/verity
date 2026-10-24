/**
 * compromised-site-detector.js — Bitdefender-Grade Compromised CMS Deep-Path & PHP Mailer Phishing Detector
 *
 * Catches phishing kits hosted inside hacked legitimate websites (e.g. WordPress, Joomla, cPanel)
 * that bypass domain-age, TLD, and entropy filters by leveraging high-reputation aged domains.
 *
 * Identifies:
 *   1. CMS Injection Path Anomalies (/wp-content/uploads/..., /wp-includes/..., /cgi-bin/...)
 *   2. Deep Subdirectory Nesting (pathDepth >= 3 with dropper endpoints)
 *   3. Phishing Kit Droppers / Mailer Endpoints (post.php, next.php, send.php, gate.php)
 *   4. Sensitive Credential Forms or Financial/Govt Brand Impersonation on Compromised Paths
 */

'use strict';

import { isTrustedTopDomain } from './rules.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { isAuthorizedPaymentGatewayOrMerchant } from '../shared/payment-gateway-allowlist.js';

export const CMS_INJECTION_PATHS = [
  '/wp-content/',
  '/wp-includes/',
  '/cgi-bin/',
  '/vendor/phpunit/',
  '/vendor/',
  '/modules/',
  '/components/',
  '/uploads/',
  '/assets/',
  '/temp/',
  '/cache/',
  '/images/',
  '/fonts/',
  '/media/'
];

export const SUSPICIOUS_SCRIPT_ENDPOINTS = [
  'post.php',
  'next.php',
  'action.php',
  'send.php',
  'mail.php',
  'log.php',
  'result.php',
  'step2.php',
  'verify.php',
  'gate.php',
  'submit.php',
  'login.php',
  'process.php',
  'auth.php'
];

export const HIGH_VALUE_IMPERSONATED_BRANDS = [
  'sbi', 'hdfc', 'icici', 'axis', 'pnb', 'bob', 'canara', 'kotak', 'yesbank', 'indusind',
  'netbanking', 'banking', 'bank',
  'incometax', 'income tax', 'parivahan', 'epfo', 'aadhaar', 'uidai', 'digilocker', 'passport',
  'microsoft', 'office365', 'office 365', 'outlook', 'onedrive', 'sharepoint',
  'google', 'gmail', 'gdrive', 'yahoo', 'apple', 'icloud', 'netflix', 'paypal', 'chase', 'wellsfargo',
  'facebook', 'instagram', 'whatsapp', 'telegram'
];

/**
 * Detects whether a URL represents a phishing kit deployed on a compromised host or CMS.
 *
 * @param {string} urlString - Target URL
 * @param {object} [domSignals={}] - Optional DOM signals from page scanner
 * @returns {{
 *   detected: boolean,
 *   score: number,
 *   signal: string|null,
 *   reasons: string[],
 *   indicators: {
 *     hasCmsInjectionPath: boolean,
 *     pathDepth: number,
 *     hasPhpOrGateEndpoint: boolean,
 *     matchedPath: string|null,
 *     matchedEndpoint: string|null
 *   }
 * }}
 */
export function detectCompromisedHostPhishing(urlString, domSignals = {}) {
  let url;
  try {
    url = new URL(urlString);
  } catch (_) {
    return {
      detected: false,
      score: 0,
      signal: null,
      reasons: [],
      indicators: { hasCmsInjectionPath: false, pathDepth: 0, hasPhpOrGateEndpoint: false, matchedPath: null, matchedEndpoint: null }
    };
  }

  // Only inspect standard HTTP/HTTPS schemes
  if (!['http:', 'https:'].includes(url.protocol)) {
    return {
      detected: false,
      score: 0,
      signal: null,
      reasons: [],
      indicators: { hasCmsInjectionPath: false, pathDepth: 0, hasPhpOrGateEndpoint: false, matchedPath: null, matchedEndpoint: null }
    };
  }

  const hostname = url.hostname.toLowerCase().replace(/^www\./, '');
  const pathname = url.pathname.toLowerCase();

  // Exclude verified top global domains, legit allowlisted domains, and payment gateways
  if (isTrustedTopDomain(hostname) || isAllowlistedDomain(hostname) || isAuthorizedPaymentGatewayOrMerchant(hostname, domSignals)) {
    return {
      detected: false,
      score: 0,
      signal: null,
      reasons: [],
      indicators: { hasCmsInjectionPath: false, pathDepth: 0, hasPhpOrGateEndpoint: false, matchedPath: null, matchedEndpoint: null }
    };
  }

  // 1. CMS Injection Path Anomaly
  const matchedPath = CMS_INJECTION_PATHS.find(p => pathname.includes(p)) ||
    (pathname.includes('/wp-admin/') && (pathname.split('/').filter(Boolean).length > 2 || pathname.endsWith('.php') && !pathname.endsWith('/wp-admin/index.php'))) ||
    null;
  const hasCmsInjectionPath = !!matchedPath;

  // 2. Deep Subdirectory Nesting (pathDepth >= 4 or >= 3 with dropper)
  const segments = pathname.split('/').filter(Boolean);
  const pathDepth = segments.length;
  const lastSegment = segments[segments.length - 1] || '';

  // 3. Phishing Kit Dropper / Mailer Script Endpoint
  const formAction = (domSignals?.formAction || '').toLowerCase();
  const matchedEndpoint = SUSPICIOUS_SCRIPT_ENDPOINTS.find(ep =>
    lastSegment === ep ||
    pathname.endsWith('/' + ep) ||
    formAction.endsWith('/' + ep) ||
    formAction === ep
  ) || null;
  const hasPhpOrGateEndpoint = !!matchedEndpoint;

  // 4. Sensitive inputs or brand impersonation check
  const hasSensitiveInputs = !!(
    domSignals?.hasPasswordInput ||
    domSignals?.hasOtpInput ||
    domSignals?.hasPinInput ||
    domSignals?.hasCredentialCollection ||
    domSignals?.hasSensitiveInputs ||
    domSignals?.loginFormCount > 0 ||
    domSignals?.paymentFields?.card ||
    domSignals?.paymentFields?.cvv ||
    domSignals?.paymentFields?.otp ||
    domSignals?.paymentFields?.pin ||
    domSignals?.universalDomPhishGraph?.hasSensitiveInputs
  );

  // Check if URL path or DOM mentions high-value brands
  const textCorpus = `${pathname} ${domSignals?.pageTitle || ''} ${domSignals?.headingText || ''} ${domSignals?.pageText || ''} ${domSignals?.textMentionsBrand || ''}`.toLowerCase();
  const matchedBrand = HIGH_VALUE_IMPERSONATED_BRANDS.find(brand => {
    // Exact word or boundary match to avoid false collisions
    const regex = new RegExp(`(?:^|[^a-z0-9])${brand}(?:[^a-z0-9]|$)`, 'i');
    return regex.test(textCorpus);
  });
  const hasBrandMention = !!matchedBrand;

  const reasons = [];

  // ── High-Accuracy Detection Invariant ──────────────────────────────────────
  // Case A: CMS asset/upload directory hosting credential form or brand trap
  // Case B: Deeply nested directory (>= 3 levels) ending in post.php / gate.php dropper with credential form or brand trap
  const isCompromisedStructure = hasCmsInjectionPath || (pathDepth >= 3 && hasPhpOrGateEndpoint);
  const isPhishingTrap = hasSensitiveInputs || hasBrandMention;

  if (isCompromisedStructure && isPhishingTrap) {
    if (hasCmsInjectionPath) {
      reasons.push(`Compromised CMS directory anomaly: Credential harvesting trap deployed inside static asset path "${matchedPath}".`);
    }
    if (hasPhpOrGateEndpoint) {
      reasons.push(`Suspicious phishing kit gate/mailer endpoint: "${matchedEndpoint}".`);
    }
    if (pathDepth >= 4) {
      reasons.push(`Deeply nested path obfuscation (depth: ${pathDepth} subdirectories).`);
    }
    if (hasBrandMention) {
      reasons.push(`High-value brand impersonation ("${matchedBrand}") on compromised third-party host.`);
    }

    return {
      detected: true,
      score: 88,
      signal: 'SIG_COMPROMISED_CMS_HOST_PHISH',
      reasons,
      hasCmsInjectionPath,
      pathDepth,
      hasPhpOrGateEndpoint,
      indicators: {
        hasCmsInjectionPath,
        pathDepth,
        hasPhpOrGateEndpoint,
        matchedPath: typeof matchedPath === 'string' ? matchedPath : (hasCmsInjectionPath ? '/wp-admin/' : null),
        matchedEndpoint
      }
    };
  }

  return {
    detected: false,
    score: 0,
    signal: null,
    reasons: [],
    hasCmsInjectionPath,
    pathDepth,
    hasPhpOrGateEndpoint,
    indicators: {
      hasCmsInjectionPath,
      pathDepth,
      hasPhpOrGateEndpoint,
      matchedPath: typeof matchedPath === 'string' ? matchedPath : null,
      matchedEndpoint
    }
  };
}

export default {
  CMS_INJECTION_PATHS,
  SUSPICIOUS_SCRIPT_ENDPOINTS,
  HIGH_VALUE_IMPERSONATED_BRANDS,
  detectCompromisedHostPhishing
};
