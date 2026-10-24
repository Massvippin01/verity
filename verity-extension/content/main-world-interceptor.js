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
  const TRUSTED_DOMAINS_REGEX = /(^|\.)(google\.[a-z.]+|bing\.com|duckduckgo\.com|yahoo\.com|brave\.com|youtube\.com|youtube-nocookie\.com|youtu\.be|vimeo\.com|player\.vimeo\.com|dailymotion\.com|twitch\.tv|github\.com|microsoft\.com|live\.com|office\.com|apple\.com|amazon\.[a-z.]+|wikipedia\.org|reddit\.com|chatgpt\.com|openai\.com|claude\.ai|gemini\.google\.com)$/i;

  function isTrustedSearchOrTopDomain(hostname) {
    if (!hostname || typeof hostname !== 'string') return false;
    return TRUSTED_DOMAINS_REGEX.test(hostname.toLowerCase());
  }

  if (typeof location !== 'undefined' && isTrustedSearchOrTopDomain(location.hostname)) {
    return;
  }

  // ── Step 0: Trap Element.prototype.attachShadow to break closed ShadowDOM cloaking ──
  if (typeof Element !== 'undefined' && Element.prototype && Element.prototype.attachShadow) {
    const origAttachShadow = Element.prototype.attachShadow;
    const origAttachShadowToString = Function.prototype.toString.bind(origAttachShadow);

    const patchedAttachShadow = function attachShadow(init) {
      const forcedInit = init ? Object.assign({}, init, { mode: 'open' }) : { mode: 'open' };
      return origAttachShadow.call(this, forcedInit);
    };

    try {
      Object.defineProperty(patchedAttachShadow, 'name', { value: 'attachShadow', configurable: true });
      Object.defineProperty(patchedAttachShadow, 'toString', {
        value: function toString() {
          return origAttachShadowToString();
        },
        configurable: true,
        writable: true
      });
    } catch (_) {}

    Element.prototype.attachShadow = patchedAttachShadow;
  }

  // Prevent multiple injections
  if (window.__VERITY_MAIN_INTERCEPTOR_ACTIVE__) return;
  Object.defineProperty(window, '__VERITY_MAIN_INTERCEPTOR_ACTIVE__', {
    value: true,
    writable: false,
    configurable: false
  });

  // Strict phishing webhook exfiltration endpoints regex
  const EXFIL_REGEX = /api\.telegram\.org\/bot|discord(app)?\.com\/api\/webhooks|webhook\.site|pipedream\.net|hookbin\.com|requestcatcher\.com/i;

  function isExfilEndpoint(url) {
    if (!url || typeof url !== 'string') return false;
    return EXFIL_REGEX.test(url);
  }

  // ── Step 0.05: Wrap WebSocket Constructor ──────────────────────────────────
  function wrapWebSocket(ctx) {
    if (!ctx || typeof ctx.WebSocket !== 'function' || ctx.WebSocket.__verityWrapped) return;

    const OrigWebSocket = ctx.WebSocket;

    const WrappedWebSocket = function (url, protocols) {
      if (!(this instanceof WrappedWebSocket)) {
        throw new TypeError("Failed to construct 'WebSocket': Please use the 'new' operator");
      }

      const targetUrl = typeof url === 'string' ? url : (url ? String(url) : '');
      if (isExfilEndpoint(targetUrl)) {
        notifyThreat('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: targetUrl });
        const err = typeof DOMException !== 'undefined'
          ? new DOMException('Blocked by Verity Security Shield: Phishing exfiltration endpoint', 'SecurityError')
          : new Error('Blocked by Verity Security Shield: Phishing exfiltration endpoint');
        throw err;
      }

      return arguments.length > 1
        ? new OrigWebSocket(url, protocols)
        : new OrigWebSocket(url);
    };

    // Preserve prototype chain
    WrappedWebSocket.prototype = OrigWebSocket.prototype;
    try {
      Object.setPrototypeOf(WrappedWebSocket, OrigWebSocket);
    } catch (_) {}

    // Preserve standard static constants
    WrappedWebSocket.CONNECTING = OrigWebSocket.CONNECTING !== undefined ? OrigWebSocket.CONNECTING : 0;
    WrappedWebSocket.OPEN = OrigWebSocket.OPEN !== undefined ? OrigWebSocket.OPEN : 1;
    WrappedWebSocket.CLOSING = OrigWebSocket.CLOSING !== undefined ? OrigWebSocket.CLOSING : 2;
    WrappedWebSocket.CLOSED = OrigWebSocket.CLOSED !== undefined ? OrigWebSocket.CLOSED : 3;

    // Preserve any additional static properties
    try {
      const descriptors = Object.getOwnPropertyDescriptors(OrigWebSocket);
      for (const prop of Object.keys(descriptors)) {
        if (!['prototype', 'name', 'length'].includes(prop)) {
          try {
            Object.defineProperty(WrappedWebSocket, prop, descriptors[prop]);
          } catch (_) {
            WrappedWebSocket[prop] = OrigWebSocket[prop];
          }
        }
      }
    } catch (_) {}

    // Preserve instanceof checks
    try {
      Object.defineProperty(WrappedWebSocket, Symbol.hasInstance, {
        value: function (instance) {
          return instance instanceof OrigWebSocket;
        },
        configurable: true
      });
    } catch (_) {}

    // Wrap WebSocket.prototype.send to inspect outbound websocket frames
    if (OrigWebSocket.prototype && !OrigWebSocket.prototype.__veritySendWrapped) {
      const origSend = OrigWebSocket.prototype.send;
      OrigWebSocket.prototype.send = function (data) {
        if (typeof data === 'string') {
          const lower = data.toLowerCase();
          const hasCred = lower.includes('password') || lower.includes('passwd') || lower.includes('otp') || lower.includes('pin=') || lower.includes('cvv');
          const isWebhookOrCrossExfil = lower.includes('api.telegram.org') || lower.includes('discord.com/api/webhooks') || lower.includes('webhook.site') || (this.url && isExfilEndpoint(this.url));
          if (hasCred && isWebhookOrCrossExfil) {
            notifyThreat('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: this.url || 'websocket_endpoint', payloadExcerpt: data.slice(0, 50) });
            return; // Drop exfiltration packet
          }
        }
        return origSend.apply(this, arguments);
      };
      OrigWebSocket.prototype.__veritySendWrapped = true;
    }

    try {
      Object.defineProperty(WrappedWebSocket, '__verityWrapped', { value: true, configurable: true });
    } catch (_) {
      WrappedWebSocket.__verityWrapped = true;
    }

    try {
      Object.defineProperty(ctx, 'WebSocket', {
        value: WrappedWebSocket,
        configurable: true,
        writable: true
      });
    } catch (_) {
      ctx.WebSocket = WrappedWebSocket;
    }
  }

  // ── Step 0.1: Context Hardening (Freeze fetch and protect against iframe recovery) ──
  function hardenContext(ctx) {
    if (!ctx || ctx.__VERITY_CTX_HARDENED__) return;
    try {
      ctx.__VERITY_CTX_HARDENED__ = true;
      if (typeof ctx.fetch === 'function') {
        const origFetch = ctx.fetch;
        const wrappedFetch = function (resource, _init) {
          let targetUrl = '';
          if (typeof resource === 'string') {
            targetUrl = resource;
          } else if (resource && typeof resource.url === 'string') {
            targetUrl = resource.url;
          }
          if (isExfilEndpoint(targetUrl)) {
            notifyThreat('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: targetUrl });
            return Promise.reject(new TypeError('Blocked by Verity Security Shield: Phishing exfiltration endpoint'));
          }
          return origFetch.apply(this, arguments);
        };

        try {
          Object.defineProperty(ctx, 'fetch', {
            value: wrappedFetch,
            configurable: false,
            writable: false
          });
        } catch (_) {
          ctx.fetch = wrappedFetch;
        }
      }

      if (typeof ctx.WebSocket === 'function') {
        wrapWebSocket(ctx);
      }
    } catch (_) {}
  }

  // Trap dynamically added iframes to prevent pristine prototype extraction
  if (typeof Node !== 'undefined' && Node.prototype) {
    const origAppendChild = Node.prototype.appendChild;
    Node.prototype.appendChild = function (child) {
      const res = origAppendChild.apply(this, arguments);
      if (child && child.tagName === 'IFRAME' && child.contentWindow) {
        try { hardenContext(child.contentWindow); } catch (_) {}
      }
      return res;
    };

    const origInsertBefore = Node.prototype.insertBefore;
    Node.prototype.insertBefore = function (newNode, referenceNode) {
      const res = origInsertBefore.apply(this, arguments);
      if (newNode && newNode.tagName === 'IFRAME' && newNode.contentWindow) {
        try { hardenContext(newNode.contentWindow); } catch (_) {}
      }
      return res;
    };
  }

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

  // ── 2. Intercept and Harden window.fetch ───────────────────────────────────
  hardenContext(window);

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

  // ── 4b. Intercept WebSocket (Exfiltration Guard) ───────────────────────────
  if (typeof window !== 'undefined' && typeof window.WebSocket === 'function') {
    wrapWebSocket(window);
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

  // ── 6b. Anti-Doxxing WebRTC & Surveillance Trap for "Digital Arrest" Scams ──
  function detectDigitalArrestSurveillanceTrap(pageText = '', requestedPermissions = [], targetHostname = '') {
    const host = (targetHostname || (typeof location !== 'undefined' ? location.hostname : '') || '').toLowerCase().replace(/^www\./, '');
    const isGov = host.endsWith('.gov.in') || host.endsWith('.nic.in') || host === 'gov.in' || host === 'nic.in';
    if (isGov) return { detected: false };

    const text = String(pageText || '').toLowerCase();
    const SURVEILLANCE_LURES = [
      'digital arrest', 'cbi', 'police', 'supreme court', 'high court', 'courtroom', 'virtual court',
      'arrest warrant', 'customs', 'narcotics', 'ed notice', 'crime branch', 'money laundering',
      'kyc verification', 'rbi safe account', 'trai disconnection', 'cyber crime',
      'सीबीआई', 'डिजिटल अरेस्ट', 'पुलिस', 'वारंट', 'न्यायालय',
      'சிபிஐ', 'டிஜிட்டல் கைது', 'காவல்துறை', 'நீதிமன்றம்'
    ];

    const matchedLure = SURVEILLANCE_LURES.find(l => text.includes(l));
    if (!matchedLure) return { detected: false };

    let perms = [];
    if (Array.isArray(requestedPermissions)) {
      perms = requestedPermissions.map(p => String(p).toLowerCase());
    } else if (requestedPermissions && typeof requestedPermissions === 'object') {
      if (requestedPermissions.video) perms.push('camera');
      if (requestedPermissions.audio) perms.push('microphone');
      if (requestedPermissions.geolocation) perms.push('geolocation');
    }

    const hasSurveillance = perms.length === 0 || perms.some(p =>
      p.includes('cam') || p.includes('video') || p.includes('mic') || p.includes('audio') || p.includes('geo') || p.includes('loc')
    );

    if (hasSurveillance) {
      return {
        detected: true,
        signal: 'SIG_SURVEILLANCE_EXTORTION_TRAP',
        score: 90,
        verdict: 'danger',
        reason: `Digital Arrest surveillance extortion trap detected: Unauthorized webcam/microphone or location surveillance requested under fake authority "${matchedLure}".`,
        matchedLure,
        requestedPermissions: perms
      };
    }
    return { detected: false };
  }

  if (typeof window !== 'undefined') {
    window.detectDigitalArrestSurveillanceTrap = detectDigitalArrestSurveillanceTrap;
  }

  if (typeof navigator !== 'undefined' && navigator.mediaDevices && typeof navigator.mediaDevices.getUserMedia === 'function') {
    const origGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = function (constraints) {
      const pageText = (document.body ? (document.body.innerText || '') : '').toLowerCase();
      const check = detectDigitalArrestSurveillanceTrap(pageText, constraints || ['camera', 'microphone']);
      if (check.detected) {
        notifyThreat('SIG_SURVEILLANCE_EXTORTION_TRAP', { reason: check.reason, permissions: check.requestedPermissions });
        return Promise.reject(new DOMException('Webcam/Microphone surveillance blocked by Verity Security Shield on unauthorized domain', 'NotAllowedError'));
      }
      return origGetUserMedia.apply(this, arguments);
    };
  }

  if (typeof navigator !== 'undefined' && navigator.geolocation && typeof navigator.geolocation.getCurrentPosition === 'function') {
    const origGetCurrentPosition = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
    navigator.geolocation.getCurrentPosition = function (successCb, errorCb, options) {
      const pageText = (document.body ? (document.body.innerText || '') : '').toLowerCase();
      const check = detectDigitalArrestSurveillanceTrap(pageText, ['geolocation']);
      if (check.detected) {
        notifyThreat('SIG_SURVEILLANCE_EXTORTION_TRAP', { reason: check.reason, permissions: ['geolocation'] });
        if (typeof errorCb === 'function') {
          errorCb({ code: 1, message: 'Geolocation blocked by Verity Security Shield on unauthorized domain' });
        }
        return;
      }
      return origGetCurrentPosition.apply(this, arguments);
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

  // ── 7b. Web3 & Crypto Wallet Drainer Interceptor (Ethereum & Solana) ───────
  function hookWeb3Provider() {
    if (typeof window === 'undefined') return;

    // Selector hashes for ERC-20 / ERC-721 token and NFT approvals:
    // 0x095ea7b3 = approve(address,uint256)
    // 0xa22cb465 = setApprovalForAll(address,bool)
    // 0xd505accf = permit(...)
    const APPROVAL_SELECTORS = /^0x(095ea7b3|a22cb465|d505accf)/i;

    function wrapEthProvider(provider) {
      if (!provider || provider.__verityWrapped) return provider;
      const origRequest = provider.request;
      if (typeof origRequest === 'function') {
        provider.request = new Proxy(origRequest, {
          apply(target, thisArg, args) {
            const payload = args[0] || {};
            const method = String(payload.method || '');
            const params = payload.params || [];

            if (method === 'eth_sign') {
              notifyThreat('SIG_WEB3_DRAINER_RAW_SIGN', {
                type: 'WEB3_DRAINER_RAW_SIGN',
                method,
                reason: 'Malicious Web3 drainer raw hash signing (eth_sign) intercepted.'
              });
            } else if (method === 'eth_sendTransaction' && params[0]?.data) {
              if (APPROVAL_SELECTORS.test(params[0].data)) {
                notifyThreat('SIG_WEB3_UNLIMITED_APPROVAL', {
                  type: 'WEB3_UNLIMITED_APPROVAL',
                  method,
                  data: params[0].data.slice(0, 10),
                  reason: 'Malicious Web3 wallet unlimited asset approval or permit intercepted.'
                });
              }
            }
            return Reflect.apply(target, thisArg, args);
          }
        });
      }
      try {
        Object.defineProperty(provider, '__verityWrapped', { value: true, enumerable: false, configurable: true });
      } catch (_) {
        provider.__verityWrapped = true;
      }
      return provider;
    }

    function wrapSolanaProvider(provider) {
      if (!provider || provider.__veritySolanaWrapped) return provider;
      const methodsToWrap = ['signTransaction', 'signAllTransactions', 'signMessage'];
      for (const m of methodsToWrap) {
        if (typeof provider[m] === 'function') {
          const origFn = provider[m];
          provider[m] = function () {
            if (isSuspiciousHostContext()) {
              notifyThreat('SIG_WEB3_DRAINER_RAW_SIGN', {
                type: 'WEB3_DRAINER_RAW_SIGN',
                method: m,
                reason: `Malicious Solana drainer signature (${m}) intercepted on suspicious domain.`
              });
            }
            return origFn.apply(this, arguments);
          };
        }
      }
      try {
        Object.defineProperty(provider, '__veritySolanaWrapped', { value: true, enumerable: false, configurable: true });
      } catch (_) {
        provider.__veritySolanaWrapped = true;
      }
      return provider;
    }

    if (window.ethereum) wrapEthProvider(window.ethereum);
    let currentEth = window.ethereum;
    try {
      Object.defineProperty(window, 'ethereum', {
        configurable: true,
        enumerable: true,
        get() { return currentEth; },
        set(val) { currentEth = wrapEthProvider(val); }
      });
    } catch (_) {}

    if (window.solana) wrapSolanaProvider(window.solana);
    let currentSol = window.solana;
    try {
      Object.defineProperty(window, 'solana', {
        configurable: true,
        enumerable: true,
        get() { return currentSol; },
        set(val) { currentSol = wrapSolanaProvider(val); }
      });
    } catch (_) {}
  }

  hookWeb3Provider();

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
