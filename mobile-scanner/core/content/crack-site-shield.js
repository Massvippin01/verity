/**
 * content/crack-site-shield.js — Crack, Warez & Piracy Website Malware Shield
 *
 * Protects users visiting crack, keygen, torrent, or APK-mod sites by detecting:
 * Trap A: Encrypted Archive Password Stealer Lures (LummaStealer/RedLine evasion)
 * Trap B: Invisible Full-Screen Clickjack Ad Overlays
 * Trap C: Fake Cross-Origin Download Button Traps (Ad-rotators / Malicious Executables)
 * Trap D: Fake Notification / Captcha Download Gates (Push Notification Spam Hijack)
 *
 * Compatible with Node.js ESM test suites and classic extension content scripts.
 */

import { getDomain } from '../shared/psl.js';

const ROTATOR_TLDS = [
  '.xyz', '.top', '.click', '.sbs', '.cfd', '.icu', '.buzz', '.monster', '.live', '.fun', '.cam'
];

const ARCHIVE_PASSWORD_PATTERNS = [
  /archive\s*password(?:\s*is|\s*:|\s*=\s*|\s+)?\s*[:\w\d]+/i,
  /unzip\s*password(?:\s*is|\s*:|\s*=\s*|\s+)?\s*[:\w\d]+/i,
  /rar\s*password(?:\s*is|\s*:|\s*=\s*|\s+)?\s*[:\w\d]+/i,
  /7z\s*password(?:\s*is|\s*:|\s*=\s*|\s+)?\s*[:\w\d]+/i,
  /extract\s*password(?:\s*is|\s*:|\s*=\s*|\s+)?\s*[:\w\d]+/i,
  /password\s*for\s*(?:zip|rar|7z|archive|file)(?:\s*is|\s*:|\s*=\s*|\s+)?\s*[:\w\d]+/i,
  /\bpass(?:word)?\s*:\s*[a-zA-Z0-9_\-!@#$]+/i,
  /\bpass\s*:\s*1234\b/i,
  /zip\s*password/i
];

const ARCHIVE_EXTENSIONS = ['.zip', '.rar', '.7z', '.iso', '.exe', '.msi', '.apk'];
const CRACK_KEYWORDS = ['crack', 'keygen', 'patch', 'activator', 'loader', 'repack', 'mod apk'];

const FAKE_DOWNLOAD_LABELS = [
  /download\s*now/i,
  /fast\s*download/i,
  /direct\s*download/i,
  /high\s*speed\s*download/i,
  /download\s*(?:crack|apk|keygen|patch|full)/i
];

const NOTIFICATION_GATES = [
  /(?:click|press|hit)\s+allow\s+to\s+(?:download|verify|continue|proceed|access)/i,
  /enable\s+notifications?\s+to\s+(?:continue|download|verify|proceed)/i,
  /(?:click|press)\s+allow\s+to\s+verify\s+you\s+are\s+human/i
];

/**
 * Detects crack, warez, and piracy site malware traps.
 *
 * @param {Document|HTMLElement|object} docOrSnapshot
 * @returns {{
 *   hasArchivePasswordStealerLure: boolean,
 *   hasClickjackInvisibleOverlay: boolean,
 *   hasFakeDownloadButtonTrap: boolean,
 *   hasNotificationPermissionTrap: boolean,
 *   passwordPhrase?: string,
 *   fakeDownloadTarget?: string,
 *   detected: boolean,
 *   traps: string[],
 *   signals: string[]
 * }}
 */
export function detectCrackSiteMalwareTraps(docOrSnapshot) {
  if (!docOrSnapshot) {
    return {
      hasArchivePasswordStealerLure: false,
      hasClickjackInvisibleOverlay: false,
      hasFakeDownloadButtonTrap: false,
      hasNotificationPermissionTrap: false,
      detected: false,
      traps: [],
      signals: []
    };
  }

  // ── Extract Text Corpus ──
  let text = '';
  if (typeof docOrSnapshot.text === 'string') {
    text = docOrSnapshot.text;
  } else if (docOrSnapshot.body) {
    text = (docOrSnapshot.body.innerText || docOrSnapshot.body.textContent || '');
  } else if (typeof docOrSnapshot.innerText === 'string') {
    text = docOrSnapshot.innerText;
  } else if (typeof docOrSnapshot.textContent === 'string') {
    text = docOrSnapshot.textContent;
  }
  const textLower = text.toLowerCase();

  // Current page host if known
  let pageHost = '';
  try {
    if (docOrSnapshot.location && docOrSnapshot.location.hostname) {
      pageHost = docOrSnapshot.location.hostname.toLowerCase();
    } else if (typeof location !== 'undefined' && location.hostname) {
      pageHost = location.hostname.toLowerCase();
    }
  } catch (_) {}

  const pageRoot = pageHost ? (getDomain(pageHost) || pageHost) : '';

  // ── Collect Interactive Links / Buttons ──
  const linkCandidates = [];
  if (Array.isArray(docOrSnapshot.links)) {
    docOrSnapshot.links.forEach(l => {
      linkCandidates.push({
        text: (l.text || l.label || l.innerText || '').trim(),
        href: (l.href || l.url || '').trim()
      });
    });
  }
  if (Array.isArray(docOrSnapshot.buttons)) {
    docOrSnapshot.buttons.forEach(b => {
      linkCandidates.push({
        text: (b.text || b.label || b.innerText || '').trim(),
        href: (b.href || b.action || b.url || '').trim()
      });
    });
  }

  if (typeof docOrSnapshot.querySelectorAll === 'function') {
    try {
      const domElements = docOrSnapshot.querySelectorAll('a, button, input[type="button"], input[type="submit"], [role="button"]');
      domElements.forEach(el => {
        const t = (el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || '').trim();
        const h = el.getAttribute('href') || el.getAttribute('data-href') || el.getAttribute('action') || '';
        linkCandidates.push({ text: t, href: h });
      });
    } catch (_) {}
  }

  // ── TRAP A: Encrypted Archive Password Stealer Lure ──
  let hasArchivePasswordStealerLure = false;
  let matchedPasswordPhrase = '';
  for (const pattern of ARCHIVE_PASSWORD_PATTERNS) {
    const m = text.match(pattern);
    if (m) {
      matchedPasswordPhrase = m[0];
      break;
    }
  }

  if (matchedPasswordPhrase) {
    const hasArchiveLink = linkCandidates.some(c => {
      const h = c.href.toLowerCase();
      const t = c.text.toLowerCase();
      return ARCHIVE_EXTENSIONS.some(ext => h.includes(ext) || t.includes(ext));
    });
    const hasCrackKeywordInLinks = linkCandidates.some(c => {
      const h = c.href.toLowerCase();
      const t = c.text.toLowerCase();
      return CRACK_KEYWORDS.some(kw => h.includes(kw) || t.includes(kw));
    });
    const hasCrackKeywordInText = CRACK_KEYWORDS.some(kw => textLower.includes(kw));

    if (hasArchiveLink || hasCrackKeywordInLinks || hasCrackKeywordInText) {
      hasArchivePasswordStealerLure = true;
    }
  }

  // ── TRAP B: Invisible Clickjack Ad Overlay ──
  let hasClickjackInvisibleOverlay = false;

  const checkOverlayStyle = (styleObj) => {
    if (!styleObj) return false;
    const pos = (styleObj.position || '').toLowerCase();
    if (pos !== 'fixed' && pos !== 'absolute') return false;

    const zIndexVal = parseInt(styleObj.zIndex || styleObj['z-index'] || '0', 10);
    if (isNaN(zIndexVal) || zIndexVal < 9000) return false;

    // Check opacity / transparency
    let isTransparent = false;
    if (styleObj.opacity !== undefined) {
      const op = parseFloat(styleObj.opacity);
      if (!isNaN(op) && op <= 0.05) isTransparent = true;
    }
    const bg = (styleObj.background || styleObj.backgroundColor || styleObj['background-color'] || '').toLowerCase();
    if (bg === 'transparent' || bg.includes('rgba(0, 0, 0, 0)') || bg.includes('rgba(255, 255, 255, 0)') || bg === 'none') {
      isTransparent = true;
    }

    if (!isTransparent) return false;

    // Check viewport coverage (>= 60%)
    const width = String(styleObj.width || '').toLowerCase();
    const height = String(styleObj.height || '').toLowerCase();
    const top = String(styleObj.top || '');
    const left = String(styleObj.left || '');
    const right = String(styleObj.right || '');
    const bottom = String(styleObj.bottom || '');

    const isFullSize =
      (top === '0' || top === '0px') && (left === '0' || left === '0px') &&
      ((right === '0' || right === '0px') || (bottom === '0' || bottom === '0px') || width.includes('100%') || width.includes('100vw'));

    const isHighWidth = width.includes('100%') || width.includes('100vw') || parseInt(width, 10) >= 600 || parseFloat(width) >= 60;
    const isHighHeight = height.includes('100%') || height.includes('100vh') || parseInt(height, 10) >= 400 || parseFloat(height) >= 60;

    return isFullSize || (isHighWidth && isHighHeight) || (isHighWidth && !height) || (!width && !height && isFullSize);
  };

  // Inspect snapshot overlays
  if (Array.isArray(docOrSnapshot.overlays)) {
    for (const ov of docOrSnapshot.overlays) {
      if (checkOverlayStyle(ov.style || ov)) {
        hasClickjackInvisibleOverlay = true;
        break;
      }
    }
  }

  // Inspect DOM elements
  if (!hasClickjackInvisibleOverlay && typeof docOrSnapshot.querySelectorAll === 'function') {
    try {
      const candidates = docOrSnapshot.querySelectorAll('div, a, span, section, iframe, button');
      for (let i = 0; i < candidates.length; i++) {
        const el = candidates[i];
        const inlineStyle = el.style || {};
        if (checkOverlayStyle(inlineStyle)) {
          hasClickjackInvisibleOverlay = true;
          break;
        }
      }
    } catch (_) {}
  }

  // ── TRAP C: Fake Cross-Origin Download Button Trap ──
  let hasFakeDownloadButtonTrap = false;
  let fakeDownloadTarget = '';

  for (const candidate of linkCandidates) {
    const labelMatches = FAKE_DOWNLOAD_LABELS.some(pattern => pattern.test(candidate.text));
    if (!labelMatches) continue;

    const href = candidate.href;
    if (!href || href === '#' || href.startsWith('javascript:')) continue;

    let targetHost = '';
    let targetPath = '';
    try {
      const u = new URL(href, 'https://current-site.invalid');
      targetHost = u.hostname.toLowerCase();
      targetPath = u.pathname.toLowerCase();
    } catch (_) {
      continue;
    }

    const isIP = /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(targetHost);
    const targetRoot = getDomain(targetHost) || targetHost;
    const isDifferentHost = pageHost && targetHost && pageHost !== targetHost;
    const isRotatorTLD = ROTATOR_TLDS.some(tld => targetHost.endsWith(tld));
    const isExecutable = ['.exe', '.msi', '.scr', '.bat', '.apk', '.dmg'].some(ext => targetPath.endsWith(ext) || targetPath.includes(ext));
    const isRotatorQuery = href.toLowerCase().includes('clickid=') || href.toLowerCase().includes('subid=') || href.toLowerCase().includes('aff_id=');

    if (isIP || isRotatorTLD || isRotatorQuery || (isExecutable && isDifferentHost) || (isExecutable && targetHost.includes('rotator'))) {
      hasFakeDownloadButtonTrap = true;
      fakeDownloadTarget = href;
      break;
    }
  }

  // ── TRAP D: Fake Notification / Captcha Download Gate ──
  let hasNotificationPermissionTrap = false;
  for (const gatePattern of NOTIFICATION_GATES) {
    if (gatePattern.test(text)) {
      hasNotificationPermissionTrap = true;
      break;
    }
  }

  const traps = [];
  const signals = [];

  if (hasArchivePasswordStealerLure) {
    traps.push('ARCHIVE_PASSWORD_STEALER_LURE');
    signals.push('SIG_ARCHIVE_PASSWORD_STEALER_LURE');
  }
  if (hasClickjackInvisibleOverlay) {
    traps.push('CLICKJACK_INVISIBLE_OVERLAY');
    signals.push('SIG_CLICKJACK_INVISIBLE_OVERLAY');
  }
  if (hasFakeDownloadButtonTrap) {
    traps.push('FAKE_DOWNLOAD_BUTTON_TRAP');
    signals.push('SIG_FAKE_DOWNLOAD_BUTTON_TRAP');
  }
  if (hasNotificationPermissionTrap) {
    traps.push('NOTIFICATION_PERMISSION_TRAP');
    signals.push('SIG_NOTIFICATION_PERMISSION_TRAP');
  }

  const result = {
    hasArchivePasswordStealerLure,
    hasClickjackInvisibleOverlay,
    hasFakeDownloadButtonTrap,
    hasNotificationPermissionTrap,
    passwordPhrase: matchedPasswordPhrase,
    fakeDownloadTarget,
    detected: signals.length > 0,
    traps,
    signals
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.CrackSiteShield = result;
  }

  return result;
}

if (typeof globalThis !== 'undefined') {
  globalThis.detectCrackSiteMalwareTraps = detectCrackSiteMalwareTraps;
}

export default {
  detectCrackSiteMalwareTraps
};
