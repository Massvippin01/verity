/**
 * structural-phish-graph.js — Universal Structural DOM Graph Phishing Detector
 *
 * Language-agnostic, brand-agnostic, and zero-day detection of cloned website templates.
 * Cloned phishing pages (whether targeting unknown banks, universities, or corporate portals)
 * exhibit deterministic structural anomalies:
 *   1. Dead/Null Navigation Anchors (trapping the victim on the credential form).
 *   2. Cross-Origin Media Parasitism (hotlinking CSS/images/favicons from the victim CDN).
 *   3. External Link Escape Ratio (links pointing back to the authentic domain).
 *   4. Form Action Isolation (submitting credentials to webhooks or relative traps).
 */

import { getDomain } from '../shared/psl.js';
import { isAuthorizedPaymentGatewayOrMerchant, isLegitimateCheckoutFlow } from '../shared/payment-gateway-allowlist.js';

function extractHost(urlStr, baseHostname = '') {
  if (!urlStr || typeof urlStr !== 'string') return '';
  const trimmed = urlStr.trim();
  if (trimmed.startsWith('//')) {
    try { return new URL('https:' + trimmed).hostname.toLowerCase(); } catch (_) { return ''; }
  }
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    try { return new URL(trimmed).hostname.toLowerCase(); } catch (_) { return ''; }
  }
  return baseHostname ? baseHostname.toLowerCase() : '';
}

function areDifferentRoots(hostA, hostB) {
  if (!hostA || !hostB) return false;
  const a = hostA.toLowerCase();
  const b = hostB.toLowerCase();
  if (a === b) return false;
  const rootA = getDomain(a) || a;
  const rootB = getDomain(b) || b;
  return rootA !== rootB;
}

/**
 * Analyzes the structural DOM graph of a page or precomputed metrics object.
 *
 * @param {Document|Element|object} docOrMetrics
 * @param {string} [currentHostname='']
 * @returns {{
 *   detected: boolean,
 *   confidenceScore: number,
 *   signal: string|null,
 *   metrics: {
 *     deadLinkRatio: number,
 *     externalLinkRatio: number,
 *     externalMediaRatio: number,
 *     isFormOrphaned: boolean,
 *     totalLinks: number,
 *     totalMedia: number
 *   },
 *   reason: string|null
 * }}
 */
export function analyzeUniversalDomPhishGraph(docOrMetrics, currentHostname = '') {
  const currentHost = (currentHostname || (typeof location !== 'undefined' ? location.hostname : '') || '').toLowerCase().replace(/^www\./, '');

  let pageText = '';
  try {
    if (docOrMetrics && typeof docOrMetrics.innerText === 'string') pageText = docOrMetrics.innerText;
    else if (docOrMetrics && docOrMetrics.body && typeof docOrMetrics.body.innerText === 'string') pageText = docOrMetrics.body.innerText;
    else if (docOrMetrics && typeof docOrMetrics.pageText === 'string') pageText = docOrMetrics.pageText;
  } catch (_) {}

  // Exempt authorized payment gateways and verified checkout contexts
  if (isAuthorizedPaymentGatewayOrMerchant(currentHost, docOrMetrics) || isLegitimateCheckoutFlow(pageText, docOrMetrics)) {
    return {
      detected: false,
      confidenceScore: 0,
      signal: null,
      metrics: { deadLinkRatio: 0, externalLinkRatio: 0, externalMediaRatio: 0, isFormOrphaned: false, totalLinks: 0, totalMedia: 0 },
      reason: null
    };
  }

  let totalLinks = 0;
  let deadLinkCount = 0;
  let externalLinkCount = 0;
  let totalMedia = 0;
  let externalMediaCount = 0;
  let hasSensitiveInputs = false;
  let isFormOrphaned = false;

  // 1. Direct metrics object passed (e.g. for unit testing or worker simulation)
  if (docOrMetrics && typeof docOrMetrics === 'object' && ('deadLinkRatio' in docOrMetrics || 'metrics' in docOrMetrics)) {
    const m = docOrMetrics.metrics || docOrMetrics;
    const deadLinkRatio = typeof m.deadLinkRatio === 'number' ? m.deadLinkRatio : 0;
    const externalLinkRatio = typeof m.externalLinkRatio === 'number' ? m.externalLinkRatio : 0;
    const externalMediaRatio = typeof m.externalMediaRatio === 'number' ? m.externalMediaRatio : 0;
    const mTotalLinks = typeof m.totalLinks === 'number' ? m.totalLinks : 10;
    const mDeadLinks = typeof m.deadLinkCount === 'number' ? m.deadLinkCount : Math.round(deadLinkRatio * mTotalLinks);
    isFormOrphaned = !!m.isFormOrphaned;
    hasSensitiveInputs = !!(docOrMetrics.hasSensitiveInputs || docOrMetrics.hasPasswordInput || m.hasSensitiveInputs || m.hasPasswordInput);

    const meetsLinkRequirements = mTotalLinks >= 6 && mDeadLinks >= 4;

    const isCloneSignature = meetsLinkRequirements && (
      (deadLinkRatio >= 0.60 && (externalMediaRatio >= 0.50 || externalLinkRatio >= 0.50)) ||
      (isFormOrphaned && deadLinkRatio >= 0.55) ||
      (deadLinkRatio >= 0.70 && externalMediaRatio >= 0.40)
    );

    const detected = hasSensitiveInputs && isCloneSignature;

    return {
      detected,
      confidenceScore: detected ? 85 : 0,
      signal: detected ? 'SIG_UNIVERSAL_DOM_CLONE_PHISH' : null,
      metrics: {
        deadLinkRatio: Math.round(deadLinkRatio * 100) / 100,
        externalLinkRatio: Math.round(externalLinkRatio * 100) / 100,
        externalMediaRatio: Math.round(externalMediaRatio * 100) / 100,
        isFormOrphaned,
        totalLinks: mTotalLinks,
        totalMedia: m.totalMedia || 10
      },
      reason: detected
        ? `Universal structural clone anomaly: ${Math.round(deadLinkRatio * 100)}% dead navigation links with ${Math.round((externalMediaRatio || externalLinkRatio) * 100)}% external assets and credential inputs.`
        : null
    };
  }

  // 2. DOM Document / Node traversal
  const doc = docOrMetrics || (typeof document !== 'undefined' ? document : null);
  if (!doc || typeof doc.querySelectorAll !== 'function') {
    return {
      detected: false,
      confidenceScore: 0,
      signal: null,
      metrics: { deadLinkRatio: 0, externalLinkRatio: 0, externalMediaRatio: 0, isFormOrphaned: false, totalLinks: 0, totalMedia: 0 },
      reason: null
    };
  }

  // A. Anchors inspection
  const anchors = doc.querySelectorAll('a[href]');
  totalLinks = anchors.length;

  for (let i = 0; i < totalLinks; i++) {
    const rawHref = anchors[i].getAttribute('href') || '';
    const trimmed = rawHref.trim().toLowerCase();

    // Check dead link
    const isDead = !trimmed ||
      trimmed === '#' ||
      trimmed === 'javascript:void(0)' ||
      trimmed === 'javascript:;' ||
      trimmed === 'javascript:void(0);' ||
      trimmed.startsWith('javascript:void') ||
      trimmed.startsWith('#') ||
      trimmed === 'about:blank';

    if (isDead) {
      deadLinkCount++;
    } else {
      const linkHost = extractHost(rawHref, currentHost);
      if (linkHost && areDifferentRoots(linkHost, currentHost)) {
        externalLinkCount++;
      }
    }
  }

  // Calculate anchor ratios if total links >= 6 and deadLinkCount >= 4
  const deadLinkRatio = (totalLinks >= 6 && deadLinkCount >= 4) ? (deadLinkCount / totalLinks) : 0;
  const externalLinkRatio = totalLinks >= 6 ? (externalLinkCount / totalLinks) : 0;

  // B. Media & Asset Parasitism inspection (img, link[stylesheet], link[icon])
  const mediaElements = doc.querySelectorAll('img[src], link[rel*="stylesheet"][href], link[rel*="icon"][href]');
  totalMedia = mediaElements.length;

  for (let i = 0; i < totalMedia; i++) {
    const el = mediaElements[i];
    const srcOrHref = el.getAttribute('src') || el.getAttribute('href') || '';
    const mediaHost = extractHost(srcOrHref, currentHost);
    if (mediaHost && areDifferentRoots(mediaHost, currentHost)) {
      externalMediaCount++;
    }
  }

  const externalMediaRatio = totalMedia >= 3 ? (externalMediaCount / totalMedia) : 0;

  // C. Sensitive input inspection
  const passInputs = doc.querySelectorAll('input[type="password"]');
  const sensitiveInputs = doc.querySelectorAll('input[name*="pass" i], input[id*="pass" i], input[name*="pin" i], input[name*="otp" i], input[name*="card" i]');
  hasSensitiveInputs = passInputs.length > 0 || sensitiveInputs.length > 0;

  // D. Form Action Isolation
  const forms = doc.querySelectorAll('form');
  for (let i = 0; i < forms.length; i++) {
    const form = forms[i];
    const hasFormPass = form.querySelector('input[type="password"], input[name*="pass" i], input[name*="pin" i], input[name*="otp" i]');
    if (hasFormPass) {
      const rawAction = (form.getAttribute('action') || '').trim().toLowerCase();
      const isDeadAction = !rawAction || rawAction === '#' || rawAction.startsWith('javascript:') || rawAction === '';
      const isWebhookAction = rawAction.includes('formspree.io') || rawAction.includes('discord.com/api/webhooks') || rawAction.includes('api.telegram.org');

      if (isDeadAction || isWebhookAction) {
        if (deadLinkRatio >= 0.55 || (deadLinkRatio >= 0.40 && externalMediaRatio >= 0.50)) {
          isFormOrphaned = true;
          break;
        }
      }
    }
  }

  // Clone signature threshold
  const isCloneSignature = (totalLinks >= 6 && deadLinkCount >= 4) && (
    (deadLinkRatio >= 0.60 && (externalMediaRatio >= 0.50 || externalLinkRatio >= 0.50)) ||
    (isFormOrphaned && deadLinkRatio >= 0.55) ||
    (deadLinkRatio >= 0.70 && externalMediaRatio >= 0.40)
  );

  const detected = hasSensitiveInputs && isCloneSignature;

  return {
    detected,
    confidenceScore: detected ? 85 : 0,
    signal: detected ? 'SIG_UNIVERSAL_DOM_CLONE_PHISH' : null,
    metrics: {
      deadLinkRatio: Math.round(deadLinkRatio * 100) / 100,
      externalLinkRatio: Math.round(externalLinkRatio * 100) / 100,
      externalMediaRatio: Math.round(externalMediaRatio * 100) / 100,
      isFormOrphaned,
      totalLinks,
      totalMedia
    },
    reason: detected
      ? `Universal structural clone anomaly: ${Math.round(deadLinkRatio * 100)}% dead navigation links with ${Math.round((externalMediaRatio || externalLinkRatio) * 100)}% external assets and credential inputs.`
      : null
  };
}

export default {
  analyzeUniversalDomPhishGraph
};
