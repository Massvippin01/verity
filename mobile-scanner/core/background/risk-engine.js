import { isTrustedTopDomain, isAbusedFreeHostingOrTunnel } from './rules.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';
import { SIGNAL_CATEGORY_MAP, CATEGORY_CAPS, t } from '../shared/messages.js';
import { detectFaviconSpoof } from './favicon-matcher.js';
import { isLegitimateFederatedLogin } from './enterprise-whitelist.js';
import { HIGH_VALUE_DOM_BRANDS } from '../content/bharat-scam-detectors.js';
import { computeDomTopologyVector, runNeuralMetaFusion } from './ai-meta-fusion.js';
import { isAuthorizedPaymentGatewayOrMerchant, isLegitimateCheckoutFlow } from '../shared/payment-gateway-allowlist.js';
import { detectCompromisedHostPhishing } from './compromised-site-detector.js';
import { applyScoreFloors, DIMINISHING_WEIGHTS, THRESHOLDS, SCORE_FLOORS } from '../shared/engine-constants.js';

/**
 * @typedef {Object} RawSignal
 * @property {string} id - Unique signal identifier
 * @property {Object} params - Contextual parameters for translation/reporting
 * @property {number} score - Risk points contributed
 * @property {string} category - Risk category (url, ml, dom, etc.)
 * @property {string} source - Originating detector source
 * @property {string} reason - Human-readable reason string
 */

/**
 * @typedef {Object} RiskVerdict
 * @property {string} url - Evaluated URL
 * @property {string} hostname - Parsed domain/host
 * @property {number} score - Overall risk score [0, 100]
 * @property {number} riskScore - Mirror of score for backward compatibility
 * @property {'safe'|'caution'|'danger'} severity - Severity classification
 * @property {'safe'|'caution'|'danger'} state - State classification
 * @property {'allow'|'warn'|'block'} action - Recommended action
 * @property {RawSignal[]} signals - Emitted security signals
 * @property {Object} categories - Flagged categories with reasons
 * @property {string[]} reasons - Aggregated reason strings
 * @property {number} ruleScore - Rule-based points
 * @property {string[]} activeSources - Sources that contributed signals
 * @property {Object|null} redirectChain - Forensic redirect chain if analyzed
 * @property {boolean} shortenerDetected - Whether URL shortener was detected
 * @property {Object|null} paymentAnalysis - Payment forensics if analyzed
 */

/**
 * Fast HTML-entity and control-character sanitizer for signal parameters.
 * Prevents log injection and XSS when parameters are interpolated into UI messages.
 *
 * @param {Object} params
 * @returns {Object} Sanitized parameter map
 */
export function sanitizeSignalParams(params) {
  if (!params || typeof params !== 'object') return params;
  const clean = {};
  for (const [k, v] of Object.entries(params)) {
    if (typeof v === 'string') {
      clean[k] = v.replace(/[&<>"']/g, c => {
        switch (c) {
          case '&': return '&amp;';
          case '<': return '&lt;';
          case '>': return '&gt;';
          case '"': return '&quot;';
          case "'": return '&#39;';
          default: return c;
        }
      }).replace(/[\x00-\x1F\x7F]/g, '');
    } else {
      clean[k] = v;
    }
  }
  return clean;
}

/**
 * Scaling factor for on-device ML score (0.0 = disabled, 1.0 = standard 0-25 pts).
 */
export let ML_WEIGHT = 1.0;

export function setMlWeight(w) {
  ML_WEIGHT = w;
}

/**
 * Central Verity Risk Engine
 * 
 * Implements:
 * 1. Strict Reason ID-based categorization and routing (no English text parsing).
 * 2. Documented category caps and total score clamp [0, 100].
 * 3. Convergence Rule: Block-level verdict requires >= 2 independent sources
 *    (url, ml, dom_credentials, download, threat_intel).
 * 4. DOM text phrases alone capped at Caution (scam_language cap: 20).
 * 5. Independent Allowlist capped at Caution (max 40) unless download or credential-exfil fires.
 */
export function calculateRisk(
  url,
  ruleSignals = [],
  mlScore = null,
  domSignals = null,
  threatIntel = null,
  redirectSignals = null,
  paymentAnalysis = null,
  downloadSignals = null,
  mlWeightOverride = null,
  brandsList = []
) {
  const rawMlWeight = (mlWeightOverride !== null) ? mlWeightOverride : ML_WEIGHT;
  const isFederatedLogin = isLegitimateFederatedLogin(url);
  const activeMlWeight = isFederatedLogin ? Math.min(rawMlWeight, 0.15) : rawMlWeight;
  let hostname = '';
  try { hostname = new URL(url).hostname.toLowerCase(); } catch (e) {}
  const urlLower = (url || '').toLowerCase();

  const isAuthorizedGateway = isAuthorizedPaymentGatewayOrMerchant(hostname, domSignals);
  const isCheckout = isLegitimateCheckoutFlow(domSignals?.pageText, domSignals);

  const hasIllegalPinHardTrap = !!(
    domSignals?.hasIllegalWebPinInput ||
    domSignals?.asksForUpiPinInInput ||
    domSignals?.illegalWebPinCollection ||
    (domSignals?.rawSignals && domSignals.rawSignals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION'))
  );
  const hasWebhookHardTrap = !!(
    domSignals?.hasWebhookAction ||
    domSignals?.webhookAction ||
    domSignals?.hasPhishingKitWebhookExfil ||
    domSignals?.phishingKitWebhookExfil ||
    (domSignals?.rawSignals && domSignals.rawSignals.some(s => s.id === 'SIG_DISCORD_WEBHOOK_EXFIL' || s.id === 'SIG_TELEGRAM_BOT_EXFIL' || s.id === 'SIG_WEBHOOK_CREDENTIAL_LEAK'))
  );

  const hasActiveCompromiseTrap = !!(
    hasIllegalPinHardTrap ||
    hasWebhookHardTrap ||
    domSignals?.bitbAttack ||
    domSignals?.hasBitbAttack ||
    domSignals?.clickFix ||
    domSignals?.clickFixAttack ||
    domSignals?.hasClickfixClipboardAttack ||
    domSignals?.phishingKitWebhookExfil ||
    domSignals?.hasPhishingKitWebhookExfil ||
    domSignals?.webhookAction ||
    domSignals?.clipboardAddressSwap ||
    domSignals?.hasClipboardAddressSwap ||
    domSignals?.upiQrCollectTrap ||
    domSignals?.hasUpiCollectTrap ||
    domSignals?.surveillanceExtortionTrap ||
    domSignals?.hasSurveillanceExtortionTrap ||
    domSignals?.crossOriginPasswordReuse ||
    domSignals?.hasCrossOriginPasswordReuse ||
    domSignals?.passwordReuseTrap ||
    domSignals?.hasMaliciousFormAction ||
    domSignals?.npciUnsignedCollect ||
    domSignals?.hasUnsignedMerchantCollect ||
    domSignals?.hasDigitalArrestOverlay ||
    domSignals?.aitmReverseProxy ||
    domSignals?.hasAitmReverseProxy ||
    domSignals?.keyloggerHoneytokenTripped ||
    domSignals?.brandAssetTheft ||
    domSignals?.web3DrainerRawSign ||
    domSignals?.web3UnlimitedApproval ||
    domSignals?.crossOriginCredentialPost
  );

  // 0. Trusted Top Domain & Authorized Payment Gateway Protection Override
  if ((isTrustedTopDomain(hostname) || isAuthorizedGateway) && (!threatIntel || !threatIntel.malware) && (!downloadSignals || !downloadSignals.chromeSaysDangerous) && (!domSignals || !domSignals.hasCrossDomainCredentialAction) && !hasActiveCompromiseTrap) {
    return {
      url,
      hostname,
      score: 0,
      riskScore: 0,
      severity: 'safe',
      state: 'safe',
      action: 'allow',
      reasons: [],
      signals: [],
      categories: {
        phishing: { flagged: false, confidence: 0, reason: null },
        malware: { flagged: false, source: null },
        scamFraud: { flagged: false, reason: null },
        suspicious: { flagged: false, reason: null }
      },
      paymentAnalysis: null,
      activeSources: []
    };
  }

  const rawSignals = [];
  const categories = Object.seal({
    phishing: Object.seal({ flagged: false, confidence: 0, reason: null }),
    malware: Object.seal({ flagged: false, source: null }),
    scamFraud: Object.seal({ flagged: false, reason: null }),
    suspicious: Object.seal({ flagged: false, reason: null })
  });

  // Helper to register an emitted signal
  const emitSignal = (id, params = {}, score = 0, source = 'url', explicitCat = null) => {
    const cleanParams = sanitizeSignalParams(params);
    const category = explicitCat || SIGNAL_CATEGORY_MAP[id] || 'url';
    const reasonText = t(id, cleanParams);
    rawSignals.push({
      id,
      params: cleanParams,
      score,
      category,
      source,
      reason: reasonText
    });
  };

  // ── 1. Process URL Heuristic Rule Signals ──────────────────────────────────
  (ruleSignals || []).forEach(s => {
    if (s.triggered === false) return;
    const sigId = s.id || 'SIG_URL_SUSPICIOUS';
    const source = 'url';
    emitSignal(sigId, s.params || {}, s.score || 0, source);
  });

  // ── 1b. Free Hosting / Tunnel Credential Phishing ─────────────────────────
  const isFreeHostingOrTunnel = isAbusedFreeHostingOrTunnel(hostname);
  const freeHostPhishKeywords = ['login', 'signin', 'kyc', 'bank', 'netbanking', 'upi', 'yono', 'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'paytm', 'phonepe', 'gpay'];
  const hasFreeHostUrlLure = freeHostPhishKeywords.some(kw => urlLower.includes(kw));

  const isAllowlisted = isAllowlistedDomain(hostname);
  const hasCredentialOrBrandIndicators = !!(
    (domSignals && (
      domSignals.hasPasswordInput ||
      domSignals.hasCredentialCollection ||
      domSignals.paymentFields?.otp ||
      domSignals.paymentFields?.pin ||
      (domSignals.domBrandSpoof && domSignals.domBrandSpoof.detected) ||
      domSignals.hasBrandMismatch
    )) ||
    (paymentAnalysis && paymentAnalysis.domainMismatch)
  );

  if (isFreeHostingOrTunnel && (hasFreeHostUrlLure || hasCredentialOrBrandIndicators) && !isAllowlisted) {
    emitSignal('SIG_FREE_HOST_CREDENTIAL_PHISH', { platform: hostname }, 75, 'url', 'brand_impersonation');
    categories.phishing.flagged = true;
    categories.phishing.reason = t('SIG_FREE_HOST_CREDENTIAL_PHISH', { platform: hostname });
  }

  // ── 2. Process ML Signal ───────────────────────────────────────────────────
  if (activeMlWeight > 0 && mlScore !== null && mlScore > 30) {
    const mlScaled = Math.min(Math.round(mlScore * 0.35 * activeMlWeight), Math.round(35 * activeMlWeight));
    if (mlScaled > 0) {
      emitSignal('SIG_ML_PHISHING', { confidence: mlScore }, mlScaled, 'ml');
      categories.phishing.flagged = true;
      categories.phishing.confidence = mlScore;
    }
  }

  // ── 3. Process DOM Signals ─────────────────────────────────────────────────
  if (domSignals) {
    // A0. DOM Title / Heading Brand Spoofing (Hard Override)
    let detectedBrandSpoof = null;
    if (domSignals.domBrandSpoof && domSignals.domBrandSpoof.detected) {
      detectedBrandSpoof = domSignals.domBrandSpoof.brand || 'Official Institution';
    } else if (domSignals.hasPasswordInput || domSignals.hasCredentialCollection || domSignals.paymentFields?.otp || domSignals.paymentFields?.pin) {
      const titleAndText = ((domSignals.pageTitle || '') + ' ' + (domSignals.headingText || '')).toLowerCase();
      if (titleAndText) {
        for (const brand of HIGH_VALUE_DOM_BRANDS) {
          if (brand.patterns.some(p => titleAndText.includes(p))) {
            const isOfficial = brand.officialDomains.some(d => hostname === d || hostname.endsWith('.' + d));
            if (!isOfficial) {
              detectedBrandSpoof = brand.name;
              break;
            }
          }
        }
      }
    }

    if (detectedBrandSpoof && !isAllowlisted) {
      emitSignal('SIG_DOM_BRAND_IMPERSONATION', { brand: detectedBrandSpoof }, 85, 'dom', 'brand_impersonation');
      categories.phishing.flagged = true;
      categories.phishing.reason = t('SIG_DOM_BRAND_IMPERSONATION', { brand: detectedBrandSpoof });
    }

    // A0a. Autonomous Unlisted Brand Discovery & Impersonation (Hard Override)
    if (domSignals.autonomousBrandMismatch && domSignals.autonomousBrandMismatch.detected && !isAllowlisted) {
      const assertedBrand = domSignals.autonomousBrandMismatch.assertedBrand || 'Institutional Brand';
      emitSignal('SIG_AUTONOMOUS_BRAND_IDENTITY_MISMATCH', { brand: assertedBrand }, 85, 'dom', 'brand_impersonation');
      categories.phishing.flagged = true;
      categories.phishing.reason = t('SIG_AUTONOMOUS_BRAND_IDENTITY_MISMATCH', { brand: assertedBrand });
    }

    // A00. Cross-Origin Brand Asset Leeching & Favicon Theft (Hard Override)
    if (domSignals.brandAssetTheft && domSignals.brandAssetTheft.detected && !isAllowlisted) {
      const leechedBrand = domSignals.brandAssetTheft.leechedBrand || 'Protected Brand';
      emitSignal('SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT', { brand: leechedBrand, assetUrl: domSignals.brandAssetTheft.assetUrl }, 85, 'dom', 'brand_impersonation');
      categories.phishing.flagged = true;
      categories.phishing.reason = t('SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT', { brand: leechedBrand });
    }

    // A000. Real-time Keylogger Honeytoken Tripped
    if (domSignals.keyloggerHoneytokenTripped && !isAllowlisted) {
      emitSignal('SIG_REALTIME_KEYLOGGER_HONEYTOKEN_TRIPPED', {}, 90, 'dom', 'dom_credentials');
      categories.phishing.flagged = true;
      categories.phishing.reason = t('SIG_REALTIME_KEYLOGGER_HONEYTOKEN_TRIPPED');
    }

    // A0000. Surveillance Extortion Trap
    if (domSignals.surveillanceExtortionTrap || domSignals.hasSurveillanceExtortionTrap) {
      const phrase = domSignals.surveillanceExtortionTrap?.matchedLure || 'unauthorized surveillance';
      emitSignal('SIG_SURVEILLANCE_EXTORTION_TRAP', { phrase }, 90, 'dom', 'scam_language');
      categories.scamFraud.flagged = true;
      const trapReason = t('SIG_SURVEILLANCE_EXTORTION_TRAP', { phrase });
      categories.scamFraud.reason = categories.scamFraud.reason ? `${categories.scamFraud.reason} ${trapReason}` : trapReason;
    }

    // A00000. NPCI Unsigned Collect Forensic Trap
    if (domSignals.npciUnsignedCollect || domSignals.hasUnsignedMerchantCollect) {
      const vpa = domSignals.npciUnsignedCollect?.payeeVpa || 'unverified payee';
      emitSignal('SIG_NPCI_UNSIGNED_COLLECT_FORENSIC', { payeeVpa: vpa }, 90, 'dom', 'payment_phishing');
      categories.scamFraud.flagged = true;
      const npciReason = t('SIG_NPCI_UNSIGNED_COLLECT_FORENSIC', { payeeVpa: vpa });
      categories.scamFraud.reason = categories.scamFraud.reason ? `${categories.scamFraud.reason} ${npciReason}` : npciReason;
    }

    // A. DOM Brand Impersonation on unverified domain
    if (!domSignals.isTrustedDomain && !isAllowlisted) {
      const textAndTitle = ((domSignals.pageTitle || '') + ' ' + (domSignals.pageText || '')).toLowerCase();
      const brandKeywords = [
        { name: 'HDFC Bank', keywords: ['hdfc netbanking', 'hdfc bank', 'hdfcbank'] },
        { name: 'SBI', keywords: ['sbi netbanking', 'state bank of india', 'sbi yono', 'onlinesbi'] },
        { name: 'ICICI Bank', keywords: ['icici netbanking', 'icici bank', 'icicibank'] },
        { name: 'Axis Bank', keywords: ['axis bank', 'axisbank'] },
        { name: 'Kotak Bank', keywords: ['kotak bank', 'kotak mahindra'] },
        { name: 'PayPal', keywords: ['paypal'] },
        { name: 'Razorpay', keywords: ['razorpay'] },
        { name: 'Stripe', keywords: ['stripe checkout', 'stripe.com'] },
        { name: 'Paytm', keywords: ['paytm rewards', 'paytm cashback'] },
        { name: 'Netflix', keywords: ['netflix'] }
      ];

      for (const b of brandKeywords) {
        if (b.keywords.some(k => textAndTitle.includes(k))) {
          if (domSignals.hasCredentialCollection || domSignals.hasPasswordInput) {
            emitSignal('SIG_CONTENT_BRAND_IMPERSONATION', { brand: b.name }, 60, 'dom');
            categories.phishing.flagged = true;
            categories.phishing.reason = t('SIG_CONTENT_BRAND_IMPERSONATION', { brand: b.name });
            break;
          }
        }
      }
    }

    // Favicon MurmurHash3 & CDN Hotlink Brand Spoofing
    const faviconSpoof = detectFaviconSpoof(url, domSignals, brandsList);
    if (faviconSpoof && faviconSpoof.triggered && !isAllowlisted) {
      emitSignal(faviconSpoof.id, faviconSpoof.params || {}, faviconSpoof.score || 85, 'dom', 'brand_impersonation');
      categories.phishing.flagged = true;
      categories.phishing.reason = faviconSpoof.reason;
    }

    // B. Credential Fields on unverified domain
    if (!isAllowlisted) {
      if (domSignals.hasCredentialCollection) {
        emitSignal('SIG_CREDENTIAL_COLLECTION', {}, 15, 'dom');
      } else if (domSignals.hasPasswordInput) {
        emitSignal('SIG_PASSWORD_REQUEST', {}, 10, 'dom');
      }
      if (domSignals.loginFormCount > 0) {
        emitSignal('SIG_LOGIN_FORM', {}, 5, 'dom');
      }
    }

    // Cross-Domain Credential Exfiltration (must trigger even on allowlisted domains)
    if (domSignals.hasCrossDomainCredentialAction) {
      emitSignal('SIG_CROSS_DOMAIN_CREDENTIAL_EXFIL', { targetDomain: domSignals.exfilTargetDomain || 'external' }, 85, 'threat_intel');
      categories.phishing.flagged = true;
    }

    // Cyber Fraud & Exfiltration
    if (domSignals.kycCyberFraud && !isAllowlisted) {
      emitSignal('SIG_KYC_CYBER_FRAUD', { phrase: domSignals.kycCyberFraudReason || 'Fake KYC lure' }, 80, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.kycCyberFraudReason || 'Fake KYC/Aadhaar/PAN cyber fraud lure detected';
      const lowerReason = (domSignals.kycCyberFraudReason || '').toLowerCase();
      if (lowerReason.includes('electricity') || lowerReason.includes('digital arrest') || lowerReason.includes('cbi') || lowerReason.includes('police') || lowerReason.includes('disconnected')) {
        emitSignal('SIG_DIGITAL_ARREST_SCAM', {}, 75, 'dom');
      }
    }
    if ((domSignals.illegalWebPinCollection || domSignals.asksForUpiPinInInput || domSignals.hasIllegalWebPinInput) && !isAllowlisted) {
      emitSignal('SIG_ILLEGAL_WEB_PIN_COLLECTION', { phrase: domSignals.illegalWebPinPhrase || 'UPI PIN collection' }, 95, 'dom', 'dom_credentials');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = 'Illegal in-browser UPI PIN collection input detected';
    }
    if (domSignals.phishingKitWebhookExfil || domSignals.hasPhishingKitWebhookExfil || domSignals.webhookAction) {
      emitSignal('SIG_PHISHING_KIT_WEBHOOK_EXFIL', { endpoint: domSignals.webhookExfilEndpoint || 'Telegram/Discord webhook' }, 95, 'threat_intel');
      categories.phishing.flagged = true;
      categories.phishing.reason = 'Phishing kit exfiltration endpoint detected';
    }
    if (domSignals.techSupportRemoteScam && !isAllowlisted) {
      emitSignal('SIG_TECH_SUPPORT_REMOTE_SCAM', { helpline: domSignals.techSupportHelpline || 'helpline' }, 85, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.techSupportRemoteScamReason || 'Remote desktop tech-support scam lure detected';
    }
    if (domSignals.untrustedScreenShare) {
      emitSignal('SIG_UNTRUSTED_SCREEN_SHARE', {}, 85, 'threat_intel');
      categories.phishing.flagged = true;
      categories.phishing.reason = 'Untrusted screen sharing capture attempt';
    }
    if (domSignals.bitbAttack || domSignals.hasBitbAttack) {
      emitSignal('SIG_BITB_FAKE_WINDOW_ATTACK', { target: domSignals.bitbAttack?.target || domSignals.bitbTarget || 'identity provider' }, 95, 'dom');
      categories.phishing.flagged = true;
      categories.phishing.reason = domSignals.bitbAttack?.reason || domSignals.bitbReason || 'Browser-in-the-Browser fake authentication window detected';
    }
    if (domSignals.bitbPopupSpoof || domSignals.hasBitbPopupSpoof) {
      emitSignal('SIG_BITB_FAKE_POPUP_SPOOF', { spoofedOrigin: domSignals.bitbTarget || 'identity provider' }, 85, 'dom');
      categories.phishing.flagged = true;
      categories.phishing.reason = domSignals.bitbReason || 'Browser-in-the-Browser fake popup spoof detected';
    }
    if (domSignals.web3DrainerRawSign) {
      emitSignal('SIG_WEB3_DRAINER_RAW_SIGN', { method: domSignals.web3Method || 'eth_sign' }, 95, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = 'Malicious Web3 wallet drainer raw hash signing intercepted';
    }
    if (domSignals.web3UnlimitedApproval) {
      emitSignal('SIG_WEB3_UNLIMITED_APPROVAL', { data: domSignals.web3Data || 'approval' }, 95, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = 'Malicious Web3 wallet unlimited asset approval intercepted';
    }
    if (domSignals.crossOriginCredentialPost) {
      emitSignal('SIG_CROSS_ORIGIN_CREDENTIAL_POST', { targetUrl: domSignals.crossOriginTarget || 'untrusted endpoint' }, 95, 'dom');
      categories.phishing.flagged = true;
      categories.phishing.reason = 'Cross-origin credential post hijacking intercepted';
    }
    if (domSignals.aitmReverseProxy || domSignals.hasAitmReverseProxy) {
      emitSignal('SIG_AITM_REVERSE_PROXY_PHISH', { endpoint: domSignals.aitmReason || 'Proprietary IdP inputs' }, 95, 'dom');
      categories.phishing.flagged = true;
      categories.phishing.reason = 'AiTM reverse-proxy phishing kit detected';
    }
    if (domSignals.maliciousQrPayload && !isAllowlisted) {
      emitSignal('SIG_MALICIOUS_QR_PAYLOAD', { type: domSignals.maliciousQrType || 'Quishing' }, 85, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = 'Malicious QR code payload detected';
    }
    if (domSignals.clipboardAddressSwap || domSignals.hasClipboardAddressSwap) {
      emitSignal('SIG_CLIPBOARD_ADDRESS_SWAP', { type: domSignals.clipboardSwapType || 'Address' }, 95, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = 'Malicious clipboard address swapper detected';
    }
    if (domSignals.roguePushOrSwTrap) {
      emitSignal('SIG_ROGUE_PUSH_OR_SW_TRAP', {}, 75, 'dom');
      categories.suspicious.flagged = true;
      categories.suspicious.reason = 'Rogue push notification or service worker registration blocked';
    }
    if (domSignals.freeHostingCredentialTrap && !isAllowlisted) {
      emitSignal('SIG_FREE_HOSTING_CREDENTIAL_TRAP', { platform: domSignals.freeHostingPlatform || 'static hosting' }, 60, 'threat_intel');
      categories.phishing.flagged = true;
      categories.phishing.reason = domSignals.freeHostingReason || 'Credential harvesting trap hosted on multi-tenant free hosting platform';
    }
    if (domSignals.evasionTechniqueDetected && !isAllowlisted) {
      emitSignal('SIG_EVASION_TECHNIQUE_DETECTED', { technique: domSignals.evasionTechniqueReason || 'anti-analysis' }, 35, 'threat_intel');
      categories.phishing.flagged = true;
      categories.phishing.reason = domSignals.evasionTechniqueReason || 'Phishing kit evasion technique detected';
    }
    if (domSignals.canvasCredentialLure && !isAllowlisted) {
      emitSignal('SIG_CANVAS_CREDENTIAL_FORM', {}, 55, 'dom_credentials');
      categories.phishing.flagged = true;
      categories.phishing.reason = 'Deceptive canvas element simulating a credential form detected';
    }
    if (domSignals.digitalArrestExtortion && !isAllowlisted) {
      emitSignal('SIG_DIGITAL_ARREST_EXTORTION', { phrase: domSignals.digitalArrestPhrase || 'fake law enforcement warrant' }, 85, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.digitalArrestReason || 'Digital Arrest extortion scam pattern detected';
    }
    if (domSignals.maliciousApkDropper && !isAllowlisted) {
      emitSignal('SIG_MALICIOUS_APK_DROPPER', { filename: domSignals.maliciousApkFilename || 'unverified APK' }, 90, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.maliciousApkReason || 'Malicious Android APK dropper detected';
    }
    if (domSignals.upiQrCollectTrap || domSignals.hasUpiCollectTrap) {
      emitSignal('SIG_UPI_QR_COLLECT_TRAP', { lurePhrase: domSignals.upiQrLure || 'cashback/refund QR trap' }, 85, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.upiQrReason || 'Deceptive UPI QR code collect trap detected';
    }

    // Crack / Warez / Piracy Site Shield Traps
    const crackTraps = domSignals.crackSiteTraps || {};
    if ((crackTraps.hasArchivePasswordStealerLure || domSignals.archivePasswordStealerLure) && !isAllowlisted) {
      emitSignal('SIG_ARCHIVE_PASSWORD_STEALER_LURE', { phrase: crackTraps.passwordPhrase || 'archive password lure' }, 90, 'dom', 'scam_language');
      categories.scamFraud.flagged = true;
      categories.malware.flagged = true;
      categories.malware.source = 'Archive password stealer lure';
    }
    if ((crackTraps.hasClickjackInvisibleOverlay || domSignals.clickjackInvisibleOverlay) && !isAllowlisted) {
      emitSignal('SIG_CLICKJACK_INVISIBLE_OVERLAY', {}, 80, 'dom', 'malvertising');
      categories.suspicious.flagged = true;
    }
    if ((crackTraps.hasFakeDownloadButtonTrap || domSignals.fakeDownloadButtonTrap) && !isAllowlisted) {
      emitSignal('SIG_FAKE_DOWNLOAD_BUTTON_TRAP', { target: crackTraps.fakeDownloadTarget || 'ad-rotator/executable' }, 85, 'dom', 'malvertising');
      categories.scamFraud.flagged = true;
    }
    if ((crackTraps.hasNotificationPermissionTrap || domSignals.notificationPermissionTrap) && !isAllowlisted) {
      emitSignal('SIG_NOTIFICATION_PERMISSION_TRAP', {}, 80, 'dom', 'malvertising');
      categories.suspicious.flagged = true;
    }

    // Universal Structural DOM Graph Phishing Detector (Phase 1)
    if ((domSignals.universalDomPhishGraph?.detected || domSignals.universalDomClonePhish) && !isAllowlisted) {
      emitSignal('SIG_UNIVERSAL_DOM_CLONE_PHISH', {}, 85, 'dom', 'dom_credentials');
      categories.phishing.flagged = true;
      categories.phishing.confidence = Math.max(categories.phishing.confidence, 85);
      categories.phishing.reason = domSignals.universalDomPhishGraph?.reason || 'Universal structural clone anomaly with dead navigation links and credential form.';
    }

    // Universal Behavioral Security Guard (Phase 3)
    if ((domSignals.universalClipboardMismatch || domSignals.clipboardMismatch) && !isAllowlisted) {
      emitSignal('SIG_UNIVERSAL_CLIPBOARD_MISMATCH', {}, 85, 'dom', 'scam_language');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = 'Silent clipboard substitution with untrusted command, URL, or address.';
    }
    if (domSignals.crossOriginPasswordReuse || domSignals.passwordReuseTrap || domSignals.hasCrossOriginPasswordReuse) {
      const orig = domSignals.crossOriginPasswordReuse?.originalOrigin || domSignals.passwordReuseOrigin || 'authentic origin';
      emitSignal('SIG_CROSS_ORIGIN_PASSWORD_REUSE_TRAP', { originalOrigin: orig }, 95, 'dom', 'dom_credentials');
      categories.phishing.flagged = true;
      categories.phishing.confidence = 95;
      categories.phishing.reason = `Zero-Knowledge Credential Guard: Password previously registered for ${orig} re-entered on untrusted origin.`;
    }

    // C. Scam Language / PUP / ClickFix
    if (domSignals.clickFixAttack || domSignals.clickFix || domSignals.hasClickfixClipboardAttack) {
      emitSignal('SIG_CLICKFIX_CLIPBOARD_ATTACK', { phrase: domSignals.clickFixReason }, 85, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.clickFixReason || 'ClickFix clipboard command lure detected';
    }
    if (domSignals.scamBonusLure) {
      emitSignal('SIG_SCAM_BONUS_LURE', { phrase: domSignals.scamBonusLurePhrase }, 55, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.scamBonusLurePhrase || 'Fake bonus/reward lure detected';
    }
    if ((domSignals.hasUpiLink || domSignals.unverifiedUpiCollection) && !isAllowlisted) {
      if (domSignals.scamBonusLure || domSignals.scam || (domSignals.financialMatches && (domSignals.financialMatches.includes('cashback') || domSignals.financialMatches.includes('upi')))) {
        emitSignal('SIG_UPI_DEBIT_TRAP', {}, 75, 'dom');
        categories.scamFraud.flagged = true;
        categories.scamFraud.reason = 'UPI cashback or debit trap detected hiding a payment request';
      }
    }
    if (domSignals.scam) {
      emitSignal('SIG_SCAM_LANGUAGE', { phrase: domSignals.scamReason }, 10, 'dom');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = domSignals.scamReason;
    }
    if (domSignals.pup) {
      emitSignal('SIG_PUP', { details: domSignals.pupReason }, 5, 'dom');
      categories.suspicious.flagged = true;
      categories.suspicious.reason = domSignals.pupReason;
    }

    // D. Financial Context
    const highConfidenceFinancialTerms = ['cvv', 'otp', 'upi', 'kyc', 'atm pin', 'mpin', 'bank account', 'account number', 'ifsc', 'net banking', 'netbanking', 'credit card', 'debit card'];
    const hasHighConfidence = domSignals.financialMatches && domSignals.financialMatches.some(m => highConfidenceFinancialTerms.includes(m));

    if (!domSignals.isTrustedDomain && !isAllowlisted && domSignals.financialMatches && domSignals.financialMatches.length >= 2) {
      emitSignal('SIG_FINANCIAL_CONTEXT', { terms: domSignals.financialMatches.slice(0, 3).join(', ') }, 20, 'dom');
    }

    // E. Synergies
    const hasBrandSignal = rawSignals.some(s => s.category === 'brand_impersonation');
    if (hasBrandSignal && domSignals.hasCredentialCollection && !isAllowlisted) {
      emitSignal('SIG_SYNERGY_IMPERSONATION_CREDENTIALS', {}, 30, 'dom');
    } else if (!hasBrandSignal && domSignals.hasCredentialCollection && !isAllowlisted && domSignals.financialMatches && domSignals.financialMatches.length >= 2 && hasHighConfidence) {
      emitSignal('SIG_SYNERGY_FINANCIAL_CREDENTIALS', {}, 35, 'dom');
    }

    const isSuspiciousRedirect = redirectSignals && (redirectSignals.suspicious || (redirectSignals.shortenerDetected && redirectSignals.chain && redirectSignals.chain.length > 2));
    if (isSuspiciousRedirect && domSignals.hasCredentialCollection && !isAllowlisted) {
      emitSignal('SIG_SYNERGY_REDIRECT_CREDENTIALS', {}, 50, 'dom');
    }
  }

  // ── 4. Process Payment Protection Signals ──────────────────────────────────
  if (paymentAnalysis && paymentAnalysis.isPaymentPage && !isAllowlisted) {
    if (paymentAnalysis.structuredReasons && Array.isArray(paymentAnalysis.structuredReasons)) {
      paymentAnalysis.structuredReasons.forEach(r => {
        emitSignal(r.id, r.params || {}, r.score || 0, 'dom');
      });
    }
  }

  // ── 4b. Process Redirect Protection Signals ────────────────────────────────
  if (redirectSignals && redirectSignals.structuredReasons && Array.isArray(redirectSignals.structuredReasons)) {
    redirectSignals.structuredReasons.forEach(r => {
      emitSignal(r.id, r.params || {}, r.score || 0, r.source || 'redirect', r.category);
    });
  }
  if (redirectSignals && redirectSignals.chainForensics) {
    const cf = redirectSignals.chainForensics;
    if (cf.signals && Array.isArray(cf.signals)) {
      if (cf.signals.includes('SIG_MALVERTISING_REDIRECT_CHAIN') && !rawSignals.some(s => s.id === 'SIG_MALVERTISING_REDIRECT_CHAIN')) {
        emitSignal('SIG_MALVERTISING_REDIRECT_CHAIN', { elapsedMs: cf.elapsedMs }, 80, 'redirect', 'malvertising');
      }
      if (cf.signals.includes('SIG_TAB_UNDER_HIJACK') && !rawSignals.some(s => s.id === 'SIG_TAB_UNDER_HIJACK')) {
        emitSignal('SIG_TAB_UNDER_HIJACK', {}, 85, 'redirect', 'malvertising');
      }
    }
  }

  // ── 5. Process Threat Intelligence Signals ─────────────────────────────────
  if (threatIntel && threatIntel.malware) {
    emitSignal('THREAT_INTEL_MALWARE', { source: threatIntel.source }, 80, 'threat_intel');
    categories.malware.flagged = true;
    categories.malware.source = threatIntel.source;
  }

  // RDAP Newly-Registered-Domain (NRD) Sentinel (Phase 2)
  const rdapRisk = threatIntel?.rdapRisk || domSignals?.rdapRisk;
  const domainAgeDays = threatIntel?.domainAgeDays ?? domSignals?.domainAgeDays ?? threatIntel?.ageDays ?? domSignals?.ageDays;
  if (rdapRisk && rdapRisk.signal && !isAllowlisted) {
    emitSignal(rdapRisk.signal, { ageDays: rdapRisk.ageDays }, rdapRisk.score || (rdapRisk.hardOverride ? 85 : 45), 'threat_intel', rdapRisk.hardOverride ? 'dom_credentials' : 'url');
    if (rdapRisk.hardOverride) {
      categories.phishing.flagged = true;
      categories.phishing.confidence = Math.max(categories.phishing.confidence, 85);
      categories.phishing.reason = rdapRisk.reason || 'Newly registered domain requesting sensitive credentials';
    }
  } else if (domainAgeDays !== undefined && domainAgeDays !== null && domainAgeDays <= 14 && !isAllowlisted) {
    const hasSensitive = !!(
      (domSignals && (domSignals.hasCredentialCollection || domSignals.hasPasswordInput || domSignals.paymentFields?.card || domSignals.paymentFields?.otp || domSignals.paymentFields?.pin)) ||
      (paymentAnalysis && paymentAnalysis.isPaymentPage)
    );
    if (hasSensitive) {
      emitSignal('SIG_UNIVERSAL_NRD_CREDENTIAL_TRAP', { ageDays: domainAgeDays }, 85, 'dom', 'dom_credentials');
      categories.phishing.flagged = true;
      categories.phishing.confidence = Math.max(categories.phishing.confidence, 85);
      categories.phishing.reason = `Universal NRD Trap: Domain registered only ${domainAgeDays} day(s) ago requesting credentials.`;
    } else {
      emitSignal('SIG_NEWLY_REGISTERED_DOMAIN_CAUTION', { ageDays: domainAgeDays }, 45, 'threat_intel', 'url');
    }
  }

  // Certificate Transparency (CT) Log Ephemeral Sentinel (Phase 2)
  const ctRisk = threatIntel?.ctRisk || threatIntel?.ctLogForensics;
  if ((threatIntel?.ctEphemeralCertPhish || ctRisk?.signal === 'SIG_CT_LOG_EPHEMERAL_CERT_PHISH') && !isAllowlisted) {
    const age = ctRisk?.earliestCertAgeDays ?? ctRisk?.params?.ageDays ?? 3;
    emitSignal('SIG_CT_LOG_EPHEMERAL_CERT_PHISH', { ageDays: age }, 88, 'threat_intel', 'dom_credentials');
    categories.phishing.flagged = true;
    categories.phishing.confidence = Math.max(categories.phishing.confidence, 88);
    categories.phishing.reason = ctRisk?.reason || 'Ephemeral TLS certificate issued recently on credential-requesting domain';
  }

  // Bitdefender-Grade Compromised CMS Deep-Path Phishing Detector (Phase 1)
  const compromisedResult = detectCompromisedHostPhishing(url, domSignals);
  if (compromisedResult.detected && !isAllowlisted) {
    emitSignal('SIG_COMPROMISED_CMS_HOST_PHISH', {
      reasons: compromisedResult.reasons.join(' ')
    }, 88, 'url', 'dom_credentials');
    categories.phishing.flagged = true;
    categories.phishing.confidence = Math.max(categories.phishing.confidence, 88);
    categories.phishing.reason = compromisedResult.reasons[0] || 'Phishing kit detected inside compromised CMS/server directory';
  }

  // DNS-over-HTTPS CNAME Cloaking Sentinel (Phase 2)
  const dohRisk = threatIntel?.dohRisk || threatIntel?.dohForensics;
  if ((threatIntel?.cnameCloakingDetected || dohRisk?.signal === 'SIG_DNS_CNAME_CLOAKING_DETECTED') && !isAllowlisted) {
    const cnameTarget = dohRisk?.cname || dohRisk?.params?.cname || 'tunnel/serverless endpoint';
    emitSignal('SIG_DNS_CNAME_CLOAKING_DETECTED', { cname: cnameTarget }, 80, 'threat_intel', 'brand_impersonation');
    categories.phishing.flagged = true;
    categories.phishing.confidence = Math.max(categories.phishing.confidence, 80);
    categories.phishing.reason = dohRisk?.reason || 'DNS CNAME cloaking behind free tunnel/serverless host detected';
  }

  // Subword Character N-Gram Bayesian NLP Scam Intent (Phase 1)
  const aiNlpData = domSignals?.aiNlpScamIntent || threatIntel?.aiNlpScamIntent;
  if (aiNlpData && !isAllowlisted) {
    const prob = aiNlpData.scamProbability !== undefined ? aiNlpData.scamProbability : 0.85;
    if (prob >= 0.78) {
      emitSignal('SIG_AI_NLP_SCAM_INTENT', { probability: prob }, 82, 'dom', 'scam_language');
      categories.scamFraud.flagged = true;
      categories.scamFraud.reason = 'Continuous Subword Bayesian NLP detected high-probability scam intent';
    }
  }

  // PhishStats Public Live Threat Feed Hit (Pillar 4)
  if (threatIntel && (threatIntel.phishStatsHit || threatIntel.phishStats?.detected) && !isAllowlisted) {
    emitSignal('SIG_PHISHSTATS_LIVE_FEED_HIT', { database: 'PhishStats live feed' }, 90, 'threat_intel', 'threat_intel');
    categories.phishing.flagged = true;
    categories.phishing.confidence = Math.max(categories.phishing.confidence, 90);
    categories.phishing.reason = 'Domain listed on PhishStats live threat intelligence feed';
  }

  // Missing DMARC Credential Trap (Pillar 2/4)
  if (threatIntel && (threatIntel.missingDmarcCredentialTrap || threatIntel.dmarcRisk?.signal === 'SIG_MISSING_DMARC_CREDENTIAL_TRAP') && !isAllowlisted) {
    emitSignal('SIG_MISSING_DMARC_CREDENTIAL_TRAP', {}, 85, 'threat_intel', 'brand_impersonation');
    categories.phishing.flagged = true;
    categories.phishing.confidence = Math.max(categories.phishing.confidence, 85);
    categories.phishing.reason = 'Domain claiming institutional identity lacks a valid DMARC policy while harvesting sensitive credentials';
  }

  // SECV Psycholinguistic Coercion Signal (Pillar 1)
  const secvData = domSignals?.secvIntent || threatIntel?.secvIntent;
  if (secvData && secvData.isConvergentScam && !isAllowlisted) {
    emitSignal('SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE', {
      dominantAxis: secvData.dominantAxis || 'Coercion'
    }, Math.max(85, secvData.score || 85), 'dom', 'scam_language');
    categories.scamFraud.flagged = true;
    categories.scamFraud.reason = 'SECV 5D psycholinguistic coercion vector detected multi-axis scam convergence';
  }

  // Continuous 8D DOM Vector Embedding & Neural MLP Meta-Fusion (Phase 3)
  let neuralResult = null;
  if (!isAllowlisted && (domSignals || mlScore !== null || domainAgeDays !== null || threatIntel?.neuralFeatures || domSignals?.neuralFeatures)) {
    const domTopology = domSignals ? computeDomTopologyVector(domSignals) : null;
    const domSim = domSignals?.domCosinePhishSim ?? domTopology?.domCosinePhishSim ?? domTopology?.phishCosineSim ?? domTopology?.phishSim ?? 0;
    
    const hasCreds = (domSignals?.hasCredentialInputs !== undefined) ? domSignals.hasCredentialInputs : ((domSignals && (domSignals.hasCredentialCollection || domSignals.hasPasswordInput || domSignals.paymentFields?.card || domSignals.paymentFields?.otp || domSignals.paymentFields?.pin)) ? 1 : 0);
    const hasBrandImpression = rawSignals.some(s => s.category === 'brand_impersonation') || (domSignals && domSignals.domBrandSpoof?.detected);
    
    const metaFeatures = {
      urlOnnxProb: domSignals?.urlOnnxProb ?? (mlScore !== null ? mlScore / 100 : 0),
      markovAnomalyProb: domSignals?.markovAnomalyProb ?? (rawSignals.find(s => s.id === 'SIG_MARKOV_LEXICAL_ANOMALY' || s.id === 'RULE_MARKOV_ANOMALY')?.score ? (rawSignals.find(s => s.id === 'SIG_MARKOV_LEXICAL_ANOMALY' || s.id === 'RULE_MARKOV_ANOMALY').score / 100) : (domSignals?.markovScore ? domSignals.markovScore / 100 : 0)),
      shannonEntropyNorm: domSignals?.shannonEntropyNorm ?? 0,
      domCosinePhishSim: domSim,
      hasCredentialInputs: hasCreds,
      nlpScamProb: domSignals?.nlpScamProb ?? domSignals?.aiNlpScamIntent?.scamProbability ?? 0,
      domainNewnessDecay: domSignals?.domainNewnessDecay ?? (domainAgeDays !== undefined && domainAgeDays !== null ? Math.exp(-domainAgeDays / 14) : 0),
      cnameOrFreeHostCloak: domSignals?.cnameOrFreeHostCloak ?? ((isFreeHostingOrTunnel || threatIntel?.cnameCloakingDetected || dohRisk?.signal === 'SIG_DNS_CNAME_CLOAKING_DETECTED' || rawSignals.some(s => s.id === 'SIG_DNS_CNAME_CLOAKING_DETECTED')) ? 1 : 0),
      redirectVelocityNorm: domSignals?.redirectVelocityNorm ?? ((redirectSignals && (redirectSignals.chain?.length > 1 || redirectSignals.suspicious)) ? 0.8 : 0),
      brandProximityNorm: domSignals?.brandProximityNorm ?? (hasBrandImpression ? 0.9 : 0),
      isAuthorizedGateway: isAuthorizedGateway,
      isCheckoutFlow: isCheckout
    };

    if (threatIntel?.neuralFeatures) {
      Object.assign(metaFeatures, threatIntel.neuralFeatures);
    } else if (domSignals?.neuralFeatures) {
      Object.assign(metaFeatures, domSignals.neuralFeatures);
    }

    neuralResult = runNeuralMetaFusion(metaFeatures);
    if (neuralResult && neuralResult.threatProbability >= 0.82) {
      const fusionScore = neuralResult.score || Math.round(neuralResult.threatProbability * 100);
      emitSignal('SIG_NEURAL_META_FUSION_PHISH', { 
        probability: neuralResult.threatProbability 
      }, fusionScore, 'ml', 'dom_credentials');
      categories.phishing.flagged = true;
      categories.phishing.confidence = Math.max(categories.phishing.confidence, fusionScore);
      categories.phishing.reason = 'Continuous Neural MLP Meta-Fusion identified multi-vector zero-day phishing architecture';
    }
  }

  // ── 6. Process Download Protection Signals ──────────────────────────────────
  if (downloadSignals && downloadSignals.analysisContext === 'download') {
    if (downloadSignals.chromeSaysDangerous) {
      emitSignal('DOWNLOAD_CHROME_DANGEROUS', {}, 90, 'download');
      categories.malware.flagged = true;
    }
    if (downloadSignals.htmlSmuggling) {
      emitSignal('SIG_HTML_SMUGGLING_DOWNLOAD', { source: downloadSignals.originatingHostname || 'unverified' }, 50, 'download');
      categories.malware.flagged = true;
    }
    if (downloadSignals.remoteAccessScam) {
      emitSignal('SIG_REMOTE_ACCESS_SCAM_DOWNLOAD', { tool: downloadSignals.remoteAccessTool || 'remote access software' }, 90, 'download');
      categories.suspicious.flagged = true;
    }
    if (downloadSignals.executableDownload) {
      emitSignal('DOWNLOAD_EXECUTABLE', { filename: downloadSignals.filename }, downloadSignals.sourceDomainSuspicious ? 45 : 15, 'download');
    }
    if (downloadSignals.scriptDownload) {
      emitSignal('DOWNLOAD_SCRIPT', { filename: downloadSignals.filename, extension: downloadSignals.extension }, downloadSignals.sourceDomainSuspicious ? 40 : 15, 'download');
    }
    if (downloadSignals.installerDownload) {
      emitSignal('DOWNLOAD_INSTALLER', { filename: downloadSignals.filename, extension: downloadSignals.extension }, downloadSignals.sourceDomainSuspicious ? 50 : 35, 'download');
    }
    if (downloadSignals.doubleExtension) {
      emitSignal('DOWNLOAD_DOUBLE_EXTENSION', { apparentExtension: downloadSignals.apparentExtension, extension: downloadSignals.extension }, 55, 'download');
    }
    if (downloadSignals.contentDispositionSpoofed) {
      emitSignal('DOWNLOAD_CONTENT_DISPOSITION_SPOOF', {}, 55, 'download');
      categories.malware.flagged = true;
    }
    if (downloadSignals.misleadingFilename) {
      emitSignal('DOWNLOAD_MISLEADING_NAME', { keyword: downloadSignals.suspiciousKeyword }, 25, 'download');
    }
    if (downloadSignals.brandImpersonation) {
      emitSignal('DOWNLOAD_BRAND_IMPERSONATION', { brand: downloadSignals.brandImpersonationName }, 65, 'download');
      categories.phishing.flagged = true;
    }
    if (downloadSignals.sourceDomainMalicious) {
      emitSignal('DOWNLOAD_SOURCE_MALICIOUS', {}, 40, 'download');
      categories.malware.flagged = true;
    }
    if (downloadSignals.archiveDownload && downloadSignals.sourceDomainSuspicious) {
      emitSignal('DOWNLOAD_ARCHIVE', {}, 10, 'download');
    }
  }

  // ── 7. Group by Category and Apply Category Caps ───────────────────────────
  const pointsByCategory = {};
  const signals = [];
  const activeSources = new Set();

  for (const s of rawSignals) {
    const cat = s.category || 'url';
    pointsByCategory[cat] = (pointsByCategory[cat] || 0) + s.score;
    signals.push(s);

    if (s.score > 0) {
      if (s.source === 'redirect') {
        activeSources.add('redirect');
      }
      if (['url', 'ip_host', 'malvertising', 'brand_impersonation'].includes(cat)) {
        if (s.source !== 'redirect') {
          activeSources.add('url');
        }
      } else if (cat === 'ml') {
        activeSources.add('ml');
      } else if (cat === 'dom_credentials') {
        activeSources.add('dom_credentials');
      } else if (cat === 'payment_phishing') {
        activeSources.add('payment_phishing');
      } else if (cat === 'download') {
        activeSources.add('download');
      } else if (cat === 'threat_intel') {
        activeSources.add('threat_intel');
      }
    }
  }

  // If legitimate federated login (Okta, Ping, Azure B2C), zero out false URL token penalties
  if (isFederatedLogin) {
    pointsByCategory['url'] = 0;
  }

  // Combine capped scores across categories:
  // Sort category points descending: highest category takes full weight,
  // secondary categories add diminishing marginal risk (factor 0.4)
  // so saturation at 100 is not the normal outcome.
  const cappedScores = [];
  for (const [cat, rawPoints] of Object.entries(pointsByCategory)) {
    const cap = CATEGORY_CAPS[cat] !== undefined ? CATEGORY_CAPS[cat] : 30;
    const capped = Math.min(rawPoints, cap);
    if (capped > 0) cappedScores.push(capped);
  }
  cappedScores.sort((a, b) => b - a);

  const diminishingWeights = DIMINISHING_WEIGHTS;
  let riskScore = 0;
  for (let i = 0; i < cappedScores.length; i++) {
    const weight = i < diminishingWeights.length ? diminishingWeights[i] : 0.05;
    riskScore += Math.round(cappedScores[i] * weight);
  }

  // Pairwise Synergy Bonuses
  const hasRedirect = !!(
    (redirectSignals && (
      redirectSignals.suspicious ||
      redirectSignals.shortenerDetected ||
      redirectSignals.hasShortener ||
      redirectSignals.suspiciousIntermediateDomain ||
      redirectSignals.finalDomainSuspicious ||
      redirectSignals.popunderSpawn ||
      redirectSignals.popunderDetected ||
      (redirectSignals.chain && redirectSignals.chain.length > 1) ||
      (redirectSignals.redirectCount && redirectSignals.redirectCount > 0)
    )) ||
    activeSources.has('redirect')
  );

  // - brand_impersonation + dom_credentials: +20 pts
  if ((pointsByCategory['brand_impersonation'] || 0) > 0 && (pointsByCategory['dom_credentials'] || 0) > 0) {
    riskScore += 20;
  }
  // - payment_phishing + dom_credentials: +25 pts
  if ((pointsByCategory['payment_phishing'] || 0) > 0 && (pointsByCategory['dom_credentials'] || 0) > 0) {
    riskScore += 25;
  }
  // - malvertising + (url or ml or redirect): +20 pts
  if ((pointsByCategory['malvertising'] || 0) > 0 && ((pointsByCategory['url'] || 0) > 0 || (pointsByCategory['ml'] || 0) > 0 || hasRedirect)) {
    riskScore += 20;
  }
  // - url + ml (both >= 20): +15 pts
  if ((pointsByCategory['url'] || 0) >= 20 && (pointsByCategory['ml'] || 0) >= 20) {
    riskScore += 15;
  }

  if (hasRedirect) {
    activeSources.add('redirect');
  }

  // Hard override floors (known malware, chrome dangerous download, credential exfil, clickfix, html smuggling, content disposition spoofing)
  const isSmugglingDanger = downloadSignals && downloadSignals.htmlSmuggling && (
    downloadSignals.executableDownload ||
    downloadSignals.scriptDownload ||
    downloadSignals.installerDownload ||
    downloadSignals.archiveDownload ||
    downloadSignals.isDangerousExtension
  );

  const isSpoofDanger = downloadSignals && downloadSignals.contentDispositionSpoofed && (
    downloadSignals.executableDownload ||
    downloadSignals.scriptDownload ||
    downloadSignals.installerDownload ||
    downloadSignals.archiveDownload ||
    downloadSignals.isDangerousExtension
  );

  const hasDangerousDownload = downloadSignals && (
    downloadSignals.chromeSaysDangerous ||
    (downloadSignals.executableDownload && downloadSignals.sourceDomainMalicious) ||
    isSmugglingDanger ||
    isSpoofDanger
  );
  const hasCredentialExfil = !!(domSignals && domSignals.hasCrossDomainCredentialAction);
  const hasMalwareIntel = !!(threatIntel && threatIntel.malware);
  const hasClickFix = rawSignals.some(s => s.id === 'SIG_CLICKFIX_CLIPBOARD_ATTACK') ||
                      !!(domSignals && (domSignals.clickFixAttack || domSignals.clickFix || domSignals.hasClickfixClipboardAttack));

  // Financial & Cyber-Fraud Overrides
  const hasIllegalWebPinCollection = rawSignals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION') ||
                                    !!(domSignals && (domSignals.illegalWebPinCollection || domSignals.hasIllegalWebPinInput || domSignals.asksForUpiPinInInput));
  const hasPhishingKitWebhookExfil = rawSignals.some(s => s.id === 'SIG_PHISHING_KIT_WEBHOOK_EXFIL') ||
                                    !!(domSignals && (domSignals.phishingKitWebhookExfil || domSignals.hasPhishingKitWebhookExfil || domSignals.webhookAction));
  const hasKycCyberFraud = rawSignals.some(s => s.id === 'SIG_KYC_CYBER_FRAUD') ||
                           !!(domSignals && domSignals.kycCyberFraud);
  const hasBrandAssetHotlinkSpoof = rawSignals.some(s => s.id === 'SIG_BRAND_ASSET_HOTLINK_SPOOF') ||
                                   (paymentAnalysis && paymentAnalysis.structuredReasons && paymentAnalysis.structuredReasons.some(r => r.id === 'SIG_BRAND_ASSET_HOTLINK_SPOOF'));
  const hasTechSupportRemoteScam = rawSignals.some(s => s.id === 'SIG_TECH_SUPPORT_REMOTE_SCAM') ||
                                   !!(domSignals && domSignals.techSupportRemoteScam);
  const hasRemoteAccessScamDownload = rawSignals.some(s => s.id === 'SIG_REMOTE_ACCESS_SCAM_DOWNLOAD') ||
                                     !!(downloadSignals && downloadSignals.remoteAccessScam);
  const hasUntrustedScreenShare = rawSignals.some(s => s.id === 'SIG_UNTRUSTED_SCREEN_SHARE') ||
                                  !!(domSignals && domSignals.untrustedScreenShare);
  const hasBitbAttack = rawSignals.some(s => s.id === 'SIG_BITB_FAKE_WINDOW_ATTACK') ||
                        !!(domSignals && (domSignals.bitbAttack || domSignals.hasBitbAttack));
  const hasBitbPopupSpoof = rawSignals.some(s => s.id === 'SIG_BITB_FAKE_POPUP_SPOOF') ||
                            !!(domSignals && (domSignals.bitbPopupSpoof || domSignals.hasBitbPopupSpoof));
  const hasWeb3DrainerRawSign = rawSignals.some(s => s.id === 'SIG_WEB3_DRAINER_RAW_SIGN') ||
                                !!(domSignals && domSignals.web3DrainerRawSign);
  const hasWeb3UnlimitedApproval = rawSignals.some(s => s.id === 'SIG_WEB3_UNLIMITED_APPROVAL') ||
                                   !!(domSignals && domSignals.web3UnlimitedApproval);
  const hasCrossOriginCredentialPost = rawSignals.some(s => s.id === 'SIG_CROSS_ORIGIN_CREDENTIAL_POST') ||
                                       !!(domSignals && domSignals.crossOriginCredentialPost);
  const hasAitmReverseProxy = rawSignals.some(s => s.id === 'SIG_AITM_REVERSE_PROXY_PHISH') ||
                              !!(domSignals && (domSignals.aitmReverseProxy || domSignals.hasAitmReverseProxy));
  const hasClipboardAddressSwap = rawSignals.some(s => s.id === 'SIG_CLIPBOARD_ADDRESS_SWAP') ||
                                  !!(domSignals && (domSignals.clipboardAddressSwap || domSignals.hasClipboardAddressSwap));
  const hasMaliciousQrPayload = rawSignals.some(s => s.id === 'SIG_MALICIOUS_QR_PAYLOAD') ||
                                !!(domSignals && domSignals.maliciousQrPayload);
  const hasRoguePushOrSwTrap = rawSignals.some(s => s.id === 'SIG_ROGUE_PUSH_OR_SW_TRAP') ||
                               !!(domSignals && domSignals.roguePushOrSwTrap);
  const hasPaymentBrandMismatch = rawSignals.some(s => s.id === 'SIG_PAYMENT_BRAND_MISMATCH') ||
                                 (paymentAnalysis && paymentAnalysis.domainMismatch && paymentAnalysis.claimedProvider);
  const hasPaymentOrCredentialDemand = !!(
    (domSignals && (domSignals.hasCredentialCollection || domSignals.hasPasswordInput || domSignals.paymentFields?.card || domSignals.paymentFields?.cvv || domSignals.paymentFields?.otp || domSignals.paymentFields?.pin)) ||
    (paymentAnalysis && (paymentAnalysis.paymentFields?.card || paymentAnalysis.paymentFields?.cvv || paymentAnalysis.paymentFields?.otp || paymentAnalysis.paymentFields?.pin))
  );
  const hasBrandMismatchWithCredentials = hasPaymentBrandMismatch && hasPaymentOrCredentialDemand && !isAllowlisted;
  const hasBrandImpersonationSignal = rawSignals.some(s => s.category === 'brand_impersonation');
  const hasFaviconSpoof = rawSignals.some(s => s.id === 'SIG_FAVICON_BRAND_SPOOF');
  const hasFreeHostingTrap = rawSignals.some(s => s.id === 'SIG_FREE_HOSTING_CREDENTIAL_TRAP') || !!(domSignals && domSignals.freeHostingCredentialTrap);
  const hasFreeHostCredentialPhish = rawSignals.some(s => s.id === 'SIG_FREE_HOST_CREDENTIAL_PHISH');
  const hasDomBrandSpoof = rawSignals.some(s => s.id === 'SIG_DOM_BRAND_IMPERSONATION') || !!(domSignals && domSignals.domBrandSpoof && domSignals.domBrandSpoof.detected);
  const hasEvasionTechnique = rawSignals.some(s => s.id === 'SIG_EVASION_TECHNIQUE_DETECTED') || !!(domSignals && domSignals.evasionTechniqueDetected);
  const hasCanvasCredentialLure = rawSignals.some(s => s.id === 'SIG_CANVAS_CREDENTIAL_FORM') || !!(domSignals && domSignals.canvasCredentialLure);
  const hasDigitalArrestExtortion = rawSignals.some(s => s.id === 'SIG_DIGITAL_ARREST_EXTORTION') || !!(domSignals && domSignals.digitalArrestExtortion);
  const hasMaliciousApkDropper = rawSignals.some(s => s.id === 'SIG_MALICIOUS_APK_DROPPER') || !!(domSignals && domSignals.maliciousApkDropper);
  const hasUpiQrCollectTrap = rawSignals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP') || !!(domSignals && (domSignals.upiQrCollectTrap || domSignals.hasUpiCollectTrap));
  const hasBrandAssetTheft = rawSignals.some(s => s.id === 'SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT') || !!(domSignals && domSignals.brandAssetTheft && domSignals.brandAssetTheft.detected);
  const hasNpciForensicCollect = rawSignals.some(s => s.id === 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC') || !!(domSignals && (domSignals.npciUnsignedCollect || domSignals.hasUnsignedMerchantCollect));
  const hasKeyloggerHoneytokenTripped = rawSignals.some(s => s.id === 'SIG_REALTIME_KEYLOGGER_HONEYTOKEN_TRIPPED') || !!(domSignals && domSignals.keyloggerHoneytokenTripped);
  const hasSurveillanceExtortionTrap = rawSignals.some(s => s.id === 'SIG_SURVEILLANCE_EXTORTION_TRAP') || !!(domSignals && (domSignals.surveillanceExtortionTrap || domSignals.hasSurveillanceExtortionTrap));
  const hasUniversalDomClonePhish = rawSignals.some(s => s.id === 'SIG_UNIVERSAL_DOM_CLONE_PHISH') ||
                                   !!(domSignals && (domSignals.universalDomPhishGraph?.detected || domSignals.universalDomClonePhish));
  const hasUniversalNrdCredentialTrap = rawSignals.some(s => s.id === 'SIG_UNIVERSAL_NRD_CREDENTIAL_TRAP');
  const hasUniversalClipboardMismatch = rawSignals.some(s => s.id === 'SIG_UNIVERSAL_CLIPBOARD_MISMATCH') ||
                                        !!(domSignals && (domSignals.universalClipboardMismatch || domSignals.clipboardMismatch));
  const hasCrossOriginPasswordReuse = rawSignals.some(s => s.id === 'SIG_CROSS_ORIGIN_PASSWORD_REUSE_TRAP') ||
                                      !!(domSignals && (domSignals.crossOriginPasswordReuse || domSignals.passwordReuseTrap || domSignals.hasCrossOriginPasswordReuse));

  const hasMalvertisingRedirectChain = rawSignals.some(s => s.id === 'SIG_MALVERTISING_REDIRECT_CHAIN') ||
                                       !!(redirectSignals && redirectSignals.chainForensics && redirectSignals.chainForensics.signals && redirectSignals.chainForensics.signals.includes('SIG_MALVERTISING_REDIRECT_CHAIN'));
  const hasTabUnderHijack = rawSignals.some(s => s.id === 'SIG_TAB_UNDER_HIJACK') ||
                            !!(redirectSignals && redirectSignals.chainForensics && redirectSignals.chainForensics.signals && redirectSignals.chainForensics.signals.includes('SIG_TAB_UNDER_HIJACK'));

  const hasArchivePasswordStealerLure = rawSignals.some(s => s.id === 'SIG_ARCHIVE_PASSWORD_STEALER_LURE') ||
                                        !!(domSignals && (domSignals.archivePasswordStealerLure || domSignals.crackSiteTraps?.hasArchivePasswordStealerLure));
  const hasClickjackInvisibleOverlay = rawSignals.some(s => s.id === 'SIG_CLICKJACK_INVISIBLE_OVERLAY') ||
                                       !!(domSignals && (domSignals.clickjackInvisibleOverlay || domSignals.crackSiteTraps?.hasClickjackInvisibleOverlay));
  const hasFakeDownloadButtonTrap = rawSignals.some(s => s.id === 'SIG_FAKE_DOWNLOAD_BUTTON_TRAP') ||
                                    !!(domSignals && (domSignals.fakeDownloadButtonTrap || domSignals.crackSiteTraps?.hasFakeDownloadButtonTrap));
  const hasNotificationPermissionTrap = rawSignals.some(s => s.id === 'SIG_NOTIFICATION_PERMISSION_TRAP') ||
                                        !!(domSignals && (domSignals.notificationPermissionTrap || domSignals.crackSiteTraps?.hasNotificationPermissionTrap));

  const hasAuthSubdomain = ['login.', 'signin.', 'auth.', 'secure.', 'banking.', 'account.', 'verify.'].some(p => hostname.startsWith(p));
  const hasAuthPath = ['/auth', '/login', '/signin', '/portal', '/verification', '/logon'].some(p => urlLower.includes(p)) && (urlLower.endsWith('.php') || urlLower.endsWith('.aspx') || urlLower.includes('/auth/') || urlLower.includes('/login'));
  const hasStackedAuthHarvestTrap = hasAuthSubdomain && hasAuthPath && !isAllowlisted && !isTrustedTopDomain(hostname);
  const hasBrandCredentialPortalTrap = hasBrandImpersonationSignal && hasStackedAuthHarvestTrap;

  const hasCtEphemeralCertPhish = rawSignals.some(s => s.id === 'SIG_CT_LOG_EPHEMERAL_CERT_PHISH') ||
                                  !!(threatIntel && (threatIntel.ctEphemeralCertPhish || threatIntel.ctRisk?.signal === 'SIG_CT_LOG_EPHEMERAL_CERT_PHISH'));
  const hasDnsCnameCloaking = rawSignals.some(s => s.id === 'SIG_DNS_CNAME_CLOAKING_DETECTED') ||
                              !!(threatIntel && (threatIntel.cnameCloakingDetected || threatIntel.dohRisk?.signal === 'SIG_DNS_CNAME_CLOAKING_DETECTED'));
  const hasNeuralMetaFusionPhish = rawSignals.some(s => s.id === 'SIG_NEURAL_META_FUSION_PHISH') ||
                                   (neuralResult && neuralResult.threatProbability >= 0.82);
  const hasAiNlpScamIntent = rawSignals.some(s => s.id === 'SIG_AI_NLP_SCAM_INTENT') ||
                             !!(domSignals && domSignals.aiNlpScamIntent && (domSignals.aiNlpScamIntent.scamProbability >= 0.78));
  const hasCompromisedCmsPhish = rawSignals.some(s => s.id === 'SIG_COMPROMISED_CMS_HOST_PHISH') || (compromisedResult && compromisedResult.detected);
  const hasAutonomousBrandMismatch = rawSignals.some(s => s.id === 'SIG_AUTONOMOUS_BRAND_IDENTITY_MISMATCH') ||
                                     !!(domSignals && domSignals.autonomousBrandMismatch && domSignals.autonomousBrandMismatch.detected);
  const hasPhishStatsHit = rawSignals.some(s => s.id === 'SIG_PHISHSTATS_LIVE_FEED_HIT') ||
                           !!(threatIntel && (threatIntel.phishStatsHit || threatIntel.phishStats?.detected));
  const hasMissingDmarcCredentialTrap = rawSignals.some(s => s.id === 'SIG_MISSING_DMARC_CREDENTIAL_TRAP') ||
                                        !!(threatIntel && (threatIntel.missingDmarcCredentialTrap || threatIntel.dmarcRisk?.signal === 'SIG_MISSING_DMARC_CREDENTIAL_TRAP'));
  const hasSecvConvergence = rawSignals.some(s => s.id === 'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE') ||
                             !!(domSignals && domSignals.secvIntent && domSignals.secvIntent.isConvergentScam);

  const hasCyberFraudOverride =
    hasAutonomousBrandMismatch ||
    hasPhishStatsHit ||
    hasMissingDmarcCredentialTrap ||
    hasSecvConvergence ||
    hasIllegalWebPinCollection ||
    hasPhishingKitWebhookExfil ||
    hasCredentialExfil ||
    hasCtEphemeralCertPhish ||
    hasCompromisedCmsPhish ||
    hasDnsCnameCloaking ||
    hasNeuralMetaFusionPhish ||
    hasAiNlpScamIntent ||
    hasKycCyberFraud ||
    hasDigitalArrestExtortion ||
    hasMaliciousApkDropper ||
    hasUpiQrCollectTrap ||
    hasBrandAssetHotlinkSpoof ||
    hasFaviconSpoof ||
    hasFreeHostingTrap ||
    hasFreeHostCredentialPhish ||
    hasDomBrandSpoof ||
    hasTechSupportRemoteScam ||
    hasRemoteAccessScamDownload ||
    hasUntrustedScreenShare ||
    hasBitbAttack ||
    hasBitbPopupSpoof ||
    hasWeb3DrainerRawSign ||
    hasWeb3UnlimitedApproval ||
    hasCrossOriginCredentialPost ||
    hasAitmReverseProxy ||
    hasClipboardAddressSwap ||
    hasMaliciousQrPayload ||
    hasRoguePushOrSwTrap ||
    hasCanvasCredentialLure ||
    hasBrandAssetTheft ||
    hasNpciForensicCollect ||
    hasKeyloggerHoneytokenTripped ||
    hasSurveillanceExtortionTrap ||
    hasArchivePasswordStealerLure ||
    hasUniversalDomClonePhish ||
    hasUniversalNrdCredentialTrap ||
    hasUniversalClipboardMismatch ||
    hasCrossOriginPasswordReuse ||
    hasBrandMismatchWithCredentials ||
    hasBrandCredentialPortalTrap;

  const suspTlds = [
    '.live', '.xyz', '.monster', '.top', '.click', '.sbs', '.cfd', '.icu', '.fun', '.site', '.online',
    '.pw', '.cc', '.ws', '.biz', '.vip', '.club', '.uno', '.bar', '.qpon', '.world',
    '.tk', '.ml', '.ga', '.cf', '.gq', '.rest', '.skin', '.hair', '.boats', '.quest', '.shop', '.buzz', '.lat', '.cyou'
  ];
  const hasSuspiciousTld = suspTlds.some(tld => hostname.endsWith(tld));
  const hasPopunderAdKeyword = urlLower.includes('utm_medium=popunder') ||
                              urlLower.includes('utm_medium=popup') ||
                              urlLower.includes('propellerads') ||
                              urlLower.includes('popunder') ||
                              urlLower.includes('popads');
  let isHexQuery = false;
  try {
    const parsed = new URL(url);
    isHexQuery = /^\?[a-f0-9]{16,64}$/i.test(parsed.search);
  } catch (_) {}

  const hasMalvertisingCriticalOverride =
    (pointsByCategory['malvertising'] || 0) >= 50 ||
    hasMalvertisingRedirectChain ||
    hasTabUnderHijack ||
    hasClickjackInvisibleOverlay ||
    hasFakeDownloadButtonTrap ||
    hasNotificationPermissionTrap ||
    rawSignals.some(s => s.id === 'SIG_POPUNDER_SPAWN') ||
    rawSignals.some(s => s.id === 'SIG_MALVERTISING_REDIRECT') ||
    rawSignals.some(s => s.id === 'RULE_MALVERTISING_REDIRECT') ||
    (redirectSignals && (redirectSignals.popunderSpawn || redirectSignals.popunderDetected)) ||
    ((hasPopunderAdKeyword || isHexQuery) && hasSuspiciousTld);

  // Maximum Severity Floor Resolver (Order-Invariant)
  riskScore = applyScoreFloors(riskScore, {
    hasCrossOriginPasswordReuse,
    hasIllegalWebPinCollection,
    hasBrandCredentialPortalTrap,
    hasNeuralMetaFusionPhish,
    neuralScore: neuralResult?.score,
    hasCtEphemeralCertPhish,
    hasCompromisedCmsPhish,
    hasDnsCnameCloaking,
    hasAiNlpScamIntent,
    hasPhishingKitWebhookExfil,
    hasPhishStatsHit,
    hasAutonomousBrandMismatch,
    hasMissingDmarcCredentialTrap,
    hasSecvConvergence,
    hasKeyloggerHoneytokenTripped,
    hasSurveillanceExtortionTrap,
    hasNpciForensicCollect,
    hasArchivePasswordStealerLure,
    hasUniversalDomClonePhish,
    hasUniversalNrdCredentialTrap,
    hasUniversalClipboardMismatch,
    hasBrandAssetTheft,
    hasBitbAttack,
    hasBitbPopupSpoof,
    hasWeb3DrainerRawSign,
    hasWeb3UnlimitedApproval,
    hasCrossOriginCredentialPost,
    hasMaliciousApkDropper,
    hasDigitalArrestExtortion,
    hasUpiQrCollectTrap,
    hasTabUnderHijack,
    hasFakeDownloadButtonTrap,
    hasMalvertisingRedirectChain,
    hasClickjackInvisibleOverlay,
    hasNotificationPermissionTrap,
    hasAitmReverseProxy,
    hasClipboardAddressSwap,
    hasFaviconSpoof,
    hasPaymentOrCredentialDemand,
    hasFreeHostingTrap,
    hasBrandImpersonationSignal,
    hasPasswordInput: !!domSignals?.hasPasswordInput,
    hasCredentialCollection: !!domSignals?.hasCredentialCollection,
    hasBrandAssetHotlinkSpoof,
    hasRemoteAccessScamDownload,
    hasCredentialExfil,
    hasBrandMismatchWithCredentials,
    hasDomBrandSpoof,
    hasFreeHostCredentialPhish,
    hasKycCyberFraud,
    hasMaliciousQrPayload,
    hasTechSupportRemoteScam,
    hasUntrustedScreenShare,
    hasClickFix,
    hasRoguePushOrSwTrap,
    chromeSaysDangerous: !!(downloadSignals && downloadSignals.chromeSaysDangerous),
    isSmugglingDanger,
    isSpoofDanger,
    hasMalwareIntel,
    hasMalvertisingCriticalOverride
  });

  // Overall clamp [0, 100]
  riskScore = Math.min(Math.max(riskScore, 0), 100);

  // ── Step 4: Piracy & Clean Streaming Sites Protection ─────────────────────
  // Capped at max score 25 (SAFE / allow) when there are no phishing forms, no bank scams, and no ad rotators
  const hasPhishingForms = !!(domSignals && (domSignals.hasCredentialCollection || domSignals.hasPasswordInput || domSignals.loginFormCount > 0));
  const hasFakeBankOrScam = hasCyberFraudOverride || hasKycCyberFraud || hasTechSupportRemoteScam || hasBrandMismatchWithCredentials || hasIllegalWebPinCollection;
  const hasRotatorQuery = !!(url && (
    url.includes('utm_medium=popunder') ||
    url.includes('propellerads') ||
    url.includes('popads') ||
    url.includes('wigglepoploaderfast') ||
    /\?[a-f0-9]{16,64}/i.test(url)
  ));
  const isPurePiracyOrSuspiciousTld = signals.length > 0 && signals.every(s => 
    s.id === 'RULE_PIRACY_MEDIA' || 
    s.id === 'RULE_SUSPICIOUS_URL_PATTERN' ||
    s.id === 'SIG_URL_SUSPICIOUS'
  );

  if (isPurePiracyOrSuspiciousTld && !hasPhishingForms && !hasFakeBankOrScam && !hasRotatorQuery) {
    riskScore = Math.min(riskScore, 25);
  }

  // ── Step 4b: Legitimate Payment Gateways & Real Checkouts Protection ───────
  const hasBrandPhishOrKyc = hasPaymentBrandMismatch || hasKycCyberFraud || hasBrandMismatchWithCredentials || hasIllegalWebPinCollection;
  if ((isAuthorizedGateway || isCheckout) && !hasBrandPhishOrKyc && !hasWebhookHardTrap && !hasMalwareIntel && (!downloadSignals || !downloadSignals.chromeSaysDangerous) && !hasActiveCompromiseTrap) {
    // Suppress false-positive clone, credential, and heuristic signals for authorized gateways & real checkouts
    const falsePositiveSignalIds = new Set([
      'SIG_UNIVERSAL_DOM_CLONE_PHISH',
      'SIG_NEURAL_META_FUSION_PHISH',
      'SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT',
      'SIG_DOM_BRAND_SPOOF',
      'SIG_DOM_BRAND_IMPERSONATION',
      'SIG_CREDENTIAL_FORM_HTTP',
      'SIG_FINANCIAL_CONTEXT',
      'SIG_PAYMENT_PAGE',
      'SIG_UPI_QR_COLLECT_TRAP',
      'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC',
      'SIG_SYNERGY_FINANCIAL_CREDENTIALS',
      'SIG_SYNERGY_IMPERSONATION_CREDENTIALS'
    ]);
    for (let i = signals.length - 1; i >= 0; i--) {
      if (falsePositiveSignalIds.has(signals[i].id)) {
        signals.splice(i, 1);
      }
    }
    categories.phishing.flagged = false;
    categories.scamFraud.flagged = false;
    riskScore = Math.min(riskScore, 15);
  }

  // ── 8. Apply Convergence & Allowlist Rules ──────────────────────────────────
  // A. Independent Allowlist Rule:
  // Pages on legit_domains.json cap at Caution (max 40) unless dangerous download, credential-exfil, ClickFix, or malvertising override fires
  if (isAllowlisted && !hasDangerousDownload && !hasCredentialExfil && !hasPhishingKitWebhookExfil && !hasClickFix && !hasMalvertisingCriticalOverride && !hasRemoteAccessScamDownload && !hasBrandAssetHotlinkSpoof && !hasTechSupportRemoteScam && !hasBitbAttack && !hasAitmReverseProxy && !hasClipboardAddressSwap && !hasMaliciousQrPayload && !hasFaviconSpoof && !hasFreeHostingTrap && !hasDomBrandSpoof && !hasFreeHostCredentialPhish && !hasUpiQrCollectTrap && !hasNpciForensicCollect && !hasSurveillanceExtortionTrap && !hasCrossOriginPasswordReuse) {
    riskScore = Math.min(riskScore, 40);
  }

  // B. Convergence Rule:
  // A Block-level verdict (>= 70) strictly requires independent evidence from at least TWO sources
  // (url, ml, dom_credentials, download, threat_intel), unless a hard override fires.
  // Single-source signals can add at most Caution-level score (demoted to 65).
  // Malvertising corroborated by url (>= 20), ml (>= 15), or redirect can reach Block without dom_credentials.
  const isCorroboratedMalvertising = (pointsByCategory['malvertising'] || 0) >= 45 && (
    (pointsByCategory['url'] || 0) >= 20 ||
    (pointsByCategory['ml'] || 0) >= 15 ||
    hasRedirect
  );

  if (riskScore >= 70) {
    const hasOverride = hasMalwareIntel ||
      (downloadSignals && downloadSignals.chromeSaysDangerous) ||
      hasDangerousDownload ||
      hasCredentialExfil ||
      hasClickFix ||
      hasMalvertisingCriticalOverride ||
      hasCyberFraudOverride ||
      isCorroboratedMalvertising;
    if (!hasOverride && activeSources.size < 2) {
      // Demote to Caution
      riskScore = 65;
    }
  }

  // ── 9. Final Verdict Determination ─────────────────────────────────────────
  let severity = 'safe';
  let action = 'allow';

  if (riskScore >= 70 || (categories.malware.flagged && activeSources.has('threat_intel'))) {
    severity = 'danger';
    action = 'block';
  } else if (riskScore >= 35) {
    severity = 'caution';
    action = 'warn';
  }

  // Keep legacy category flag sync
  if (riskScore >= 70 && !categories.malware.flagged) {
    categories.phishing.flagged = true;
  }

  const reasons = signals.map(s => s.reason).filter(Boolean);

  // ── Step 3.2: Unbreakable Invariants ───────────────────────────────────────
  // 1. Allowlisted domains without explicit active compromise/exfil signals must return score 0, allow, safe
  const hasActiveRuntimeCompromise = !!(
    hasDangerousDownload ||
    hasCredentialExfil ||
    hasPhishingKitWebhookExfil ||
    hasClickFix ||
    hasBitbAttack ||
    hasAitmReverseProxy ||
    hasClipboardAddressSwap ||
    hasUpiQrCollectTrap ||
    hasNpciForensicCollect ||
    hasSurveillanceExtortionTrap ||
    hasCrossOriginPasswordReuse ||
    hasWeb3DrainerRawSign ||
    hasWeb3UnlimitedApproval ||
    hasCrossOriginCredentialPost ||
    hasDigitalArrestExtortion ||
    hasMalvertisingCriticalOverride ||
    (domSignals && (
      domSignals.hasDangerousDownload ||
      domSignals.hasCredentialExfil ||
      domSignals.hasPhishingKitWebhookExfil ||
      domSignals.webhookAction ||
      domSignals.hasClickfixClipboardAttack ||
      domSignals.clickFix ||
      domSignals.clickFixAttack ||
      domSignals.hasBitbAttack ||
      domSignals.bitbAttack ||
      domSignals.hasAitmReverseProxy ||
      domSignals.aitmReverseProxy ||
      domSignals.hasClipboardAddressSwap ||
      domSignals.clipboardAddressSwap ||
      domSignals.hasUpiCollectTrap ||
      domSignals.upiQrCollectTrap ||
      domSignals.hasUnsignedMerchantCollect ||
      domSignals.npciUnsignedCollect ||
      domSignals.hasDigitalArrestOverlay ||
      domSignals.hasSurveillanceExtortionTrap ||
      domSignals.surveillanceExtortionTrap ||
      domSignals.hasCrossOriginPasswordReuse ||
      domSignals.crossOriginPasswordReuse ||
      domSignals.passwordReuseTrap ||
      domSignals.hasMaliciousFormAction
    ))
  );

  if (isAllowlisted && !hasActiveRuntimeCompromise) {
    return {
      url,
      hostname,
      score: 0,
      riskScore: 0,
      severity: 'safe',
      state: 'safe',
      action: 'allow',
      signals: [],
      categories: {
        phishing: { flagged: false, confidence: 0, reason: null },
        malware: { flagged: false, source: null },
        scamFraud: { flagged: false, reason: null },
        suspicious: { flagged: false, reason: null }
      },
      reasons: [],
      ruleScore: 0,
      activeSources: [],
      redirectChain: null,
      shortenerDetected: false,
      paymentAnalysis: null
    };
  }

  // 2. Zero reasons must mathematically force score = 0, action = allow, severity = safe
  if (!reasons || reasons.length === 0) {
    riskScore = 0;
    severity = 'safe';
    action = 'allow';
  }

  return {
    url,
    hostname,
    score: riskScore,
    riskScore: riskScore,
    severity: severity,
    state: severity,
    action: action,
    signals: signals,
    categories: categories,
    reasons: reasons,
    ruleScore: pointsByCategory.url || 0,
    activeSources: Array.from(activeSources),
    redirectChain: redirectSignals ? redirectSignals.chain : null,
    shortenerDetected: redirectSignals ? redirectSignals.shortenerDetected : false,
    paymentAnalysis
  };
}
