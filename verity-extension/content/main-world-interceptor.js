/**
 * content/main-world-interceptor.js - Verity 2.0 MAIN World Runtime Interceptor
 *
 * Runs in the webpage's main execution context (MAIN world) at document_start.
 * Intercepts dynamic/obfuscated network exfiltration (fetch/XHR/sendBeacon),
 * live ClickFix clipboard command injection (navigator.clipboard.writeText),
 * and rogue screen capture attempts (getDisplayMedia) before page scripts can execute.
 */

(function () {
  'use strict';

  // ── Step 2.1: Immediate Early Exit on Search Engines & Top Trusted Domains ──
  const TRUSTED_DOMAINS_REGEX = /(^|\.)(google\.[a-z.]+|bing\.com|duckduckgo\.com|yahoo\.com|brave\.com|youtube\.com|youtube-nocookie\.com|youtu\.be|vimeo\.com|player\.vimeo\.com|dailymotion\.com|twitch\.tv|github\.com|microsoft\.com|live\.com|office\.com|apple\.com|amazon\.[a-z.]+|wikipedia\.org|reddit\.com|chatgpt\.com|openai\.com|claude\.ai|gemini\.google\.com|localhost|127\.0\.0\.1)$/i;

  function isTrustedSearchOrTopDomain(hostname) {
    if (!hostname || typeof hostname !== 'string') return false;
    return TRUSTED_DOMAINS_REGEX.test(hostname.toLowerCase());
  }

  if (typeof location !== 'undefined' && isTrustedSearchOrTopDomain(location.hostname)) {
    return;
  }

  // Prevent multiple injections
  if (window.__VERITY_MAIN_INTERCEPTOR_ACTIVE__) return;
  Object.defineProperty(window, '__VERITY_MAIN_INTERCEPTOR_ACTIVE__', {
    value: true,
    writable: false,
    configurable: false
  });

  // Strict phishing webhook exfiltration endpoints
  const EXFIL_ENDPOINTS = Object.freeze([
    'api.telegram.org/bot',
    'discord.com/api/webhooks',
    'discordapp.com/api/webhooks',
    'webhook.site'
  ]);

  const CLICKFIX_EXEC_PAYLOADS = Object.freeze([
    'powershell', 'mshta', 'cmd.exe', 'iex(', 'invoke-webrequest',
    'curl ', 'wget ', '-enc ', 'bypass', 'hidden'
  ]);

  // Crypto and UPI address patterns for clipboard hijacking defense
  const ADDRESS_PATTERNS = Object.freeze([
    { type: 'BTC', regex: /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/ },
    { type: 'ETH', regex: /^0x[a-fA-F0-9]{40}$/ },
    { type: 'TRON', regex: /^T[A-Za-z1-9]{33}$/ },
    { type: 'SOL', regex: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/ },
    { type: 'UPI', regex: /^[a-zA-Z0-9.-_]{2,64}@[a-zA-Z]{2,32}$/ }
  ]);

  let lastSelectedAddress = '';
  let lastSelectedAddressType = '';

  function identifyAddress(text) {
    if (!text || typeof text !== 'string') return null;
    const trimmed = text.trim();
    for (const pat of ADDRESS_PATTERNS) {
      if (pat.regex.test(trimmed)) {
        return { type: pat.type, address: trimmed };
      }
    }
    return null;
  }

  function isSuspiciousHostContext() {
    try {
      const host = (window.location.hostname || '').toLowerCase();
      const href = (window.location.href || '').toLowerCase();
      const suspTlds = ['.monster', '.xyz', '.live', '.top', '.click', '.sbs', '.cfd', '.icu', '.buzz'];
      const hasSuspTld = suspTlds.some(tld => host.endsWith(tld));
      const hasPopunderParam = href.includes('utm_medium=popunder') ||
                               href.includes('propellerads') ||
                               href.includes('popunder') ||
                               href.includes('popads');
      return hasSuspTld || hasPopunderParam;
    } catch (_) {
      return false;
    }
  }

  function isMalvertisingRotatorBridge(urlStr) {
    if (!urlStr || typeof urlStr !== 'string') return false;
    try {
      const u = new URL(urlStr, window.location.href);
      const fullPath = u.pathname + u.search;
      if (fullPath.length > 300 || /[A-Za-z0-9_\-*%]{80,}/.test(u.pathname)) {
        return true;
      }
      if (/^\?[a-f0-9]{16,64}$/i.test(u.search)) {
        return true;
      }
      const segments = u.pathname.split('/').filter(Boolean);
      const hasMixedSeg = segments.some(s => s.length >= 10 && s.length <= 35 && /[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s));
      const hasNumericCampaign = segments.some(s => /^[0-9]{4,10}$/.test(s));
      const hasParamN = Array.from(u.searchParams.keys()).some(k => /^param_[0-9]+$/i.test(k));
      if (hasMixedSeg && (hasNumericCampaign || hasParamN)) {
        return true;
      }
    } catch (_) {}
    return false;
  }

  function notifyThreat(signal, detail = {}) {
    try {
      window.dispatchEvent(new CustomEvent('__VERITY_RUNTIME_THREAT__', {
        detail: { signal, ...detail }
      }));
    } catch (_) {}
  }

  // Immediate synchronous halt at document_start for malvertising rotator bridges
  if (typeof window !== 'undefined' && window.location && isMalvertisingRotatorBridge(window.location.href)) {
    try { window.stop(); } catch (_) {}
    notifyThreat('SIG_MALVERTISING_REDIRECT', { blockedUrl: window.location.href, reason: 'Malvertising rotator bridge halted at document_start' });
  }

  function captureSelectedAddress() {
    try {
      const sel = (window.getSelection ? window.getSelection().toString() : '').trim();
      const match = identifyAddress(sel);
      if (match) {
        lastSelectedAddress = match.address;
        lastSelectedAddressType = match.type;
      }
    } catch (_) {}
  }

  document.addEventListener('selectionchange', captureSelectedAddress, true);
  document.addEventListener('copy', (e) => {
    captureSelectedAddress();
    if (lastSelectedAddress && e.clipboardData) {
      const origSetData = e.clipboardData.setData.bind(e.clipboardData);
      e.clipboardData.setData = function (format, data) {
        if (typeof data === 'string' && (format === 'text/plain' || format === 'text')) {
          const match = identifyAddress(data);
          if (match && match.address !== lastSelectedAddress) {
            notifyThreat('SIG_CLIPBOARD_ADDRESS_SWAP', {
              type: lastSelectedAddressType,
              original: lastSelectedAddress,
              swapped: match.address
            });
            return origSetData(format, lastSelectedAddress);
          }
        }
        return origSetData(format, data);
      };
    }
  }, true);

  // ── 2. Intercept window.fetch ──────────────────────────────────────────────
  if (typeof window.fetch === 'function') {
    const originalFetch = window.fetch;
    window.fetch = function (resource, _init) {
      let targetUrl = '';
      if (typeof resource === 'string') {
        targetUrl = resource;
      } else if (resource && typeof resource.url === 'string') {
        targetUrl = resource.url;
      }

      const matchedExfil = isExfilEndpoint(targetUrl);
      if (matchedExfil) {
        notifyThreat('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: targetUrl });
        return Promise.reject(new TypeError('Blocked by Verity Security Shield: Phishing exfiltration endpoint'));
      }

      return originalFetch.apply(this, arguments);
    };
  }

  // ── 3. Intercept XMLHttpRequest ────────────────────────────────────────────
  if (typeof window.XMLHttpRequest === 'function' && window.XMLHttpRequest.prototype) {
    const origOpen = window.XMLHttpRequest.prototype.open;
    const origSend = window.XMLHttpRequest.prototype.send;

    window.XMLHttpRequest.prototype.open = function (method, url) {
      this.__verityMethod = (method || 'GET').toUpperCase();
      this.__verityUrl = url;
      return origOpen.apply(this, arguments);
    };

    window.XMLHttpRequest.prototype.send = function (_body) {
      const targetUrl = this.__verityUrl || '';
      const matchedExfil = isExfilEndpoint(targetUrl);
      if (matchedExfil) {
        notifyThreat('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: targetUrl });
        throw new DOMException('Blocked by Verity Security Shield: Phishing exfiltration endpoint', 'NetworkError');
      }

      return origSend.apply(this, arguments);
    };
  }

  // ── 4. Intercept navigator.sendBeacon ──────────────────────────────────────
  if (navigator && typeof navigator.sendBeacon === 'function') {
    const origSendBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function (url, _data) {
      const targetUrl = String(url || '');
      const matchedExfil = isExfilEndpoint(targetUrl);
      if (matchedExfil) {
        notifyThreat('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: targetUrl });
        return false;
      }
      return origSendBeacon.apply(this, arguments);
    };
  }

  // ── 5. Intercept navigator.clipboard.writeText (ClickFix & Address Swap Guard) ───
  if (navigator && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    const origWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = function (text) {
      if (typeof text === 'string') {
        const lower = text.toLowerCase();
        const hasPayload = CLICKFIX_EXEC_PAYLOADS.some(p => lower.includes(p));
        if (hasPayload) {
          notifyThreat('SIG_CLICKFIX_CLIPBOARD_ATTACK', { payload: text.slice(0, 100) });
          // Overwrite with empty string to defuse malicious clipboard injection
          return origWriteText('');
        }

        // Live Crypto/UPI address swapper detection
        if (lastSelectedAddress) {
          const match = identifyAddress(text);
          if (match && match.address !== lastSelectedAddress) {
            notifyThreat('SIG_CLIPBOARD_ADDRESS_SWAP', {
              type: lastSelectedAddressType,
              original: lastSelectedAddress,
              swapped: match.address
            });
            // Overwrite with user's original selected address to defuse theft
            return origWriteText(lastSelectedAddress);
          }
        }
      }
      return origWriteText(text);
    };
  }

  // ── 6. Intercept navigator.mediaDevices.getDisplayMedia (Screen-Share Blocker)
  if (navigator && navigator.mediaDevices && typeof navigator.mediaDevices.getDisplayMedia === 'function') {
    const origGetDisplayMedia = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getDisplayMedia = function () {
      const pageText = (document.body ? (document.body.innerText || '') : '').toLowerCase();
      const isScamContext = pageText.includes('kyc') || pageText.includes('digital arrest') ||
                            pageText.includes('bank account') || pageText.includes('police') ||
                            pageText.includes('customs') || pageText.includes('cbi');
      if (isScamContext) {
        notifyThreat('SIG_UNTRUSTED_SCREEN_SHARE');
        return Promise.reject(new DOMException('Screen sharing blocked on unverified domain by Verity Security Shield', 'NotAllowedError'));
      }
      return origGetDisplayMedia.apply(this, arguments);
    };
  }

  // ── 7. Intercept Notification.requestPermission & ServiceWorker (Rogue Push Trap) ─
  if (typeof window !== 'undefined' && typeof window.Notification === 'function' && typeof window.Notification.requestPermission === 'function') {
    const origReqPerm = window.Notification.requestPermission.bind(window.Notification);
    window.Notification.requestPermission = function () {
      if (isSuspiciousHostContext()) {
        notifyThreat('SIG_ROGUE_PUSH_OR_SW_TRAP', { reason: 'Notification.requestPermission blocked on suspicious host' });
        return Promise.resolve('denied');
      }
      return origReqPerm.apply(this, arguments);
    };
  }

  if (typeof navigator !== 'undefined' && navigator.serviceWorker && typeof navigator.serviceWorker.register === 'function') {
    const origSwRegister = navigator.serviceWorker.register.bind(navigator.serviceWorker);
    navigator.serviceWorker.register = function () {
      if (isSuspiciousHostContext()) {
        notifyThreat('SIG_ROGUE_PUSH_OR_SW_TRAP', { reason: 'navigator.serviceWorker.register blocked on suspicious host' });
        return Promise.reject(new DOMException('ServiceWorker registration blocked on suspicious domain by Verity Security Shield', 'SecurityError'));
      }
      return origSwRegister.apply(this, arguments);
    };
  }

  // ── 8. Anti-Popup & Pop-Under Defusal: Intercept window.open ──────────────
  if (typeof window !== 'undefined' && typeof window.open === 'function') {
    const originalOpen = window.open;

    function isRoguePopupTarget(url, features) {
      const urlStr = url ? String(url).trim() : '';
      if (!urlStr || urlStr === 'about:blank') {
        if (typeof features === 'string' && features.length > 0) {
          const lowerFeat = features.toLowerCase();
          if (lowerFeat.includes('width=') || lowerFeat.includes('height=') ||
              lowerFeat.includes('popup=') || lowerFeat.includes('menubar=') ||
              lowerFeat.includes('toolbar=')) {
            return true;
          }
        }
        return isSuspiciousHostContext();
      }

      const lowerUrl = urlStr.toLowerCase();

      // Explicit ad-rotator and popunder indicators
      const AD_PATTERNS = [
        'utm_medium=popunder', 'propellerads', 'popads', 'adsterra', 'clickadu',
        'exoclick', 'popcash', 'hilltopads', 'richads', 'monetag', 'galaksion',
        'wigglepoploaderfast', 'bet365', '1xbet', 'dafabet', 'popunder',
        'adnetwork', 'adrotator', 'trafficjunky', 'adnxs', 'onclick'
      ];
      if (AD_PATTERNS.some(pat => lowerUrl.includes(pat))) {
        return true;
      }
      if (/\?[a-f0-9]{16,64}/i.test(urlStr)) {
        return true;
      }

      const SUSP_TLDS = ['.monster', '.click', '.sbs', '.cfd', '.rest', '.icu', '.cyou', '.buzz', '.top', '.live', '.xyz'];
      try {
        const parsed = new URL(urlStr, window.location.href);
        const host = parsed.hostname.toLowerCase();
        const curHost = window.location.hostname.toLowerCase();

        // Allow same root domain
        if (host === curHost || host.endsWith('.' + curHost) || curHost.endsWith('.' + host)) {
          return false;
        }

        // Allow official OAuth providers
        const OAUTH_PROVIDERS = /(^|\.)(accounts\.google\.com|login\.microsoftonline\.com|appleid\.apple\.com|github\.com|auth0\.com|okta\.com)$/i;
        if (OAUTH_PROVIDERS.test(host)) {
          return false;
        }

        if (SUSP_TLDS.some(tld => host.endsWith(tld))) {
          return true;
        }

        if (isSuspiciousHostContext()) {
          return true;
        }
      } catch (_) {}

      return false;
    }

    function createDummyWindow(targetUrl) {
      return {
        closed: true,
        name: '',
        opener: window,
        parent: window,
        top: window,
        focus: function () {},
        blur: function () {},
        close: function () { this.closed = true; },
        postMessage: function () {},
        addEventListener: function () {},
        removeEventListener: function () {},
        dispatchEvent: function () { return false; },
        document: {
          write: function () {},
          writeln: function () {},
          open: function () {},
          close: function () {},
          createElement: function () { return {}; },
          body: {}
        },
        location: {
          _href: targetUrl || '',
          get href() { return this._href; },
          set href(val) {
            this._href = val;
            if (isRoguePopupTarget(val, '')) {
              notifyThreat('SIG_POPUNDER_SPAWN', { blockedUrl: val });
            }
          },
          replace: function (val) { this.href = val; },
          assign: function (val) { this.href = val; },
          reload: function () {}
        }
      };
    }

    window.open = function (url, target, features) {
      const urlStr = typeof url === 'string' ? url : (url ? String(url) : '');
      const isRogue = isRoguePopupTarget(urlStr, features);

      if (isRogue) {
        let blockedHost = urlStr;
        try {
          blockedHost = urlStr ? new URL(urlStr, window.location.href).hostname : 'Untrusted origin';
        } catch (_) {}
        notifyThreat('SIG_POPUNDER_SPAWN', { blockedUrl: urlStr, hostname: blockedHost });
        return createDummyWindow(urlStr);
      }

      return originalOpen.apply(this, arguments);
    };
  }

  // ── 9. Intercept synthetic clicks on <a target="_blank"> ───────────────────
  if (typeof HTMLAnchorElement !== 'undefined' && HTMLAnchorElement.prototype) {
    const origClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () {
      const target = (this.getAttribute('target') || this.target || '').toLowerCase();
      const href = this.getAttribute('href') || this.href || '';
      if ((target === '_blank' || target === '_new') && href) {
        const lowerHref = href.toLowerCase();
        const AD_PATTERNS = [
          'utm_medium=popunder', 'propellerads', 'popads', 'adsterra', 'clickadu',
          'exoclick', 'popcash', 'hilltopads', 'richads', 'monetag', 'galaksion',
          'wigglepoploaderfast', 'bet365', '1xbet', 'dafabet', 'popunder'
        ];
        if (AD_PATTERNS.some(pat => lowerHref.includes(pat)) || /\?[a-f0-9]{16,64}/i.test(href)) {
          let blockedHost = href;
          try { blockedHost = new URL(href, window.location.href).hostname; } catch (_) {}
          notifyThreat('SIG_POPUNDER_SPAWN', { blockedUrl: href, hostname: blockedHost });
          return;
        }
      }
      return origClick.apply(this, arguments);
    };
  }

  // ── 10. Intercept rapid client-side location redirects ───────────────────
  try {
    if (typeof window !== 'undefined' && window.location) {
      const origReplace = window.location.replace.bind(window.location);
      window.location.replace = function (targetUrl) {
        if (isMalvertisingRotatorBridge(targetUrl) || (typeof isRoguePopupTarget === 'function' && isRoguePopupTarget(targetUrl, ''))) {
          try { window.stop(); } catch (_) {}
          notifyThreat('SIG_MALVERTISING_REDIRECT', { blockedUrl: targetUrl });
          return;
        }
        return origReplace(targetUrl);
      };
    }
  } catch (_) {}

  try {
    if (typeof window !== 'undefined' && window.location) {
      const origAssign = window.location.assign.bind(window.location);
      window.location.assign = function (targetUrl) {
        if (isMalvertisingRotatorBridge(targetUrl) || (typeof isRoguePopupTarget === 'function' && isRoguePopupTarget(targetUrl, ''))) {
          try { window.stop(); } catch (_) {}
          notifyThreat('SIG_MALVERTISING_REDIRECT', { blockedUrl: targetUrl });
          return;
        }
        return origAssign(targetUrl);
      };
    }
  } catch (_) {}

})();
