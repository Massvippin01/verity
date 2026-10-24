/**
 * content/bharat-scam-detectors.js — Real-Time "Digital Arrest", Fake APK & QR "Quishing" Detectors
 *
 * Specialised threat intelligence detectors for Indian cyber fraud patterns:
 * 1. Digital Arrest Extortion (CBI/ED/Police video call extortion)
 * 2. Malicious Android APK Droppers (RTO Challan, PM Kisan, Wedding Card APKs)
 * 3. UPI QR Code Collect Traps (Fake cashback/refund QR scams)
 */

'use strict';

import { analyzeUpiIntentForensics } from '../shared/upi-forensics.js';
import { isAuthorizedPaymentGatewayOrMerchant, isLegitimateCheckoutFlow } from '../shared/payment-gateway-allowlist.js';

  // ── Digital Arrest Extortion Patterns ─────────────────────────────────────
  const LAW_ENFORCEMENT_LURES = [
    'digital arrest',
    'cbi cyber crime',
    'cbi investigation',
    'narcotics parcel',
    'customs seizure warrant',
    'trai mobile disconnection',
    'money laundering investigation',
    'supreme court digital notice',
    'delhi police crime branch',
    'ed notice',
    'mha cyber cell',
    'mumbai police crime branch',
    'cyber crime cell notice',
    'interpol notice',
    'fedex narcotics parcel',
    'virtual arrest warrant',
    'narcotics control bureau notice',
    // Vernacular Hindi lures
    'डिजिटल अरेस्ट',
    'सीबीआई साइबर सेल',
    'सीबीआई',
    'कस्टम जब्ती वारंट',
    'कस्टम्स',
    'ट्राई मोबाइल डिस्कनेक्शन',
    'मनी लॉन्ड्रिंग',
    'दिल्ली पुलिस क्राइम ब्रांच',
    // Vernacular Tamil lures
    'டிஜிட்டல் கைது',
    'சிபிஐ சைபர் கிரைம்',
    'சிபிஐ',
    'சுங்கத்துறை',
    'பணப்பரிமாற்றம்',
    'டெல்லி போலீஸ்'
  ];

  const EXTORTION_DEMAND_TERMS = [
    'arrest warrant',
    'video call',
    'skype',
    'stay on call',
    'do not disconnect',
    'bail amount',
    'clearance fee',
    'transfer money to verify',
    'rbi safe account',
    'rbi verification account',
    'immediate arrest',
    'penalty of rs',
    'pay fine immediately',
    'asset freezing order',
    'virtual court',
    // Vernacular Hindi demand terms
    'गिरफ्तारी वारंट',
    'वीडियो कॉल',
    'जुर्माना भरें',
    'पैसे ट्रांसफर',
    'आरबीआई सुरक्षित खाता',
    'आरबीआई सुरक्षित खाते',
    'जमानत राशि',
    // Vernacular Tamil demand terms
    'கைது வாரண்ட்',
    'வீடியோ அழைப்பு',
    'அபராதம் செலுத்துங்கள்',
    'பணம் மாற்றவும்',
    'பிணைத் தொகை'
  ];

  // ── Malicious Indian APK Dropper Patterns ─────────────────────────────────
  const KNOWN_MALICIOUS_APKS = [
    'rto_challan.apk', 'echallan.apk', 'pm_kisan.apk', 'sbi_kyc.apk',
    'electricity_bill.apk', 'wedding_card.apk', 'aadhaar_update.apk',
    'voter_card.apk', 'bsnl_5g.apk', 'paytm_update.apk', 'pan_card.apk',
    'police_challan.apk', 'yojana.apk', 'invitation_card.apk'
  ];

  const APK_LURE_KEYWORDS = [
    'challan', 'kyc', 'kisan', 'yojana', 'police', 'bill',
    'wedding', 'card', 'aadhaar', 'update', 'subsidy', 'invitation'
  ];

  // ── UPI QR Collect Trap Patterns ──────────────────────────────────────────
  const DECEPTIVE_RECEIVE_LURES = [
    'receive cashback',
    'claim reward',
    'refund amount',
    'scan to receive',
    'olx buyer payment',
    'lottery prize',
    'scan to receive payment',
    'scan code to accept',
    'scan to accept',
    'claim bonus',
    'scan qr to get money',
    'scan to credit',
    'scan & receive',
    'claim your refund',
    'instant refund',
    'cashback won',
    // Hinglish & Tanglish lures
    'qr scan karo',
    'scan karke paise',
    'paise milega',
    'cashback milega',
    'refund aayega',
    'scan pannunga',
    'scan panna paise',
    'scan cheyandi'
  ];

  /**
   * Normalizes spaced and punctuated evasions (e.g. u.p.i -> upi, p-i-n -> pin).
   * @param {string} text
   * @returns {string}
   */
  function normalizeEvasions(text) {
    if (!text || typeof text !== 'string') return '';
    let normalized = text;
    normalized = normalized.replace(/\bu[\s._\-–—]*p[\s._\-–—]*i\b/gi, 'upi');
    normalized = normalized.replace(/\bp[\s._\-–—]*i[\s._\-–—]*n\b/gi, 'pin');
    normalized = normalized.replace(/\bm[\s._\-–—]*p[\s._\-–—]*i[\s._\-–—]*n\b/gi, 'mpin');
    normalized = normalized.replace(/\bo[\s._\-–—]*t[\s._\-–—]*p\b/gi, 'otp');
    normalized = normalized.replace(/\bk[\s._\-–—]*y[\s._\-–—]*c\b/gi, 'kyc');
    normalized = normalized.replace(/\ba[\s._\-–—]*p[\s._\-–—]*k\b/gi, 'apk');
    normalized = normalized.replace(/\bp[\s._\-–—]*a[\s._\-–—]*n\b/gi, 'pan');
    return normalized;
  }

  // ── High-Value Indian & Global Institutional Brands for DOM Spoof Traps ───
  const HIGH_VALUE_DOM_BRANDS = [
    {
      name: 'State Bank of India',
      patterns: ['state bank of india', 'onlinesbi', 'yono sbi', 'sbi netbanking', 'yono', 'भारतीय स्टेट बैंक'],
      officialDomains: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in', 'statebankofindia.com', 'bank.sbi']
    },
    {
      name: 'OnlineSBI',
      patterns: ['onlinesbi'],
      officialDomains: ['onlinesbi.sbi', 'sbi.co.in', 'sbi.bank.in']
    },
    {
      name: 'YONO SBI',
      patterns: ['yono sbi'],
      officialDomains: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in']
    },
    {
      name: 'HDFC Bank',
      patterns: ['hdfc bank', 'hdfc netbanking', 'hdfcbank'],
      officialDomains: ['hdfcbank.com', 'hdfc.bank.in', 'hdfc.com']
    },
    {
      name: 'ICICI Bank',
      patterns: ['icici bank', 'icici netbanking', 'icicibank'],
      officialDomains: ['icicibank.com', 'icici.bank.in']
    },
    {
      name: 'Axis Bank',
      patterns: ['axis bank', 'axis netbanking', 'axisbank'],
      officialDomains: ['axisbank.com', 'axis.bank.in']
    },
    {
      name: 'Kotak Mahindra',
      patterns: ['kotak mahindra', 'kotak bank', 'kotak netbanking', 'kotak 811'],
      officialDomains: ['kotak.com', 'kotak.bank.in', 'kotakbank.com']
    },
    {
      name: 'Punjab National Bank',
      patterns: ['punjab national bank', 'pnb netbanking', 'pnb bank', 'pnb one', 'पंजाब नेशनल बैंक'],
      officialDomains: ['pnbindia.in', 'pnb.bank.in', 'netpnb.com']
    },
    {
      name: 'India Post',
      patterns: ['india post', 'indiapost', 'bharatiya dak', 'भारतीय डाक', 'தபால்'],
      officialDomains: ['indiapost.gov.in', 'ippbonline.com', 'indiapostgdsonline.gov.in']
    },
    {
      name: 'Bharatiya Dak',
      patterns: ['bharatiya dak', 'भारतीय डाक'],
      officialDomains: ['indiapost.gov.in', 'ippbonline.com', 'indiapostgdsonline.gov.in']
    },
    {
      name: 'Income Tax Department',
      patterns: ['income tax department', 'incometax department', 'incometax india', 'e-filing incometax', 'आयकर विभाग'],
      officialDomains: ['incometax.gov.in', 'incometaxindia.gov.in', 'tin-nsdl.com']
    },
    {
      name: 'DigiLocker',
      patterns: ['digilocker', 'डिजिलॉकर'],
      officialDomains: ['digilocker.gov.in']
    },
    {
      name: 'Parivahan',
      patterns: ['parivahan sewa', 'parivahan', 'sarathi parivahan', 'vahan parivahan', 'e-challan parivahan', 'echallan parivahan'],
      officialDomains: ['parivahan.gov.in', 'sarathi.parivahan.gov.in', 'vahan.parivahan.gov.in', 'echallan.parivahan.gov.in']
    },
    {
      name: 'EPFO',
      patterns: ['epfo', 'epfindia', 'employees provident fund', 'कर्मचारी भविष्य निधि'],
      officialDomains: ['epfindia.gov.in']
    },
    {
      name: 'Paytm',
      patterns: ['paytm', 'paytm payments bank', 'paytm netbanking'],
      officialDomains: ['paytm.com', 'paytmbank.com']
    },
    {
      name: 'PhonePe',
      patterns: ['phonepe'],
      officialDomains: ['phonepe.com']
    },
    {
      name: 'Google Pay',
      patterns: ['google pay', 'gpay'],
      officialDomains: ['pay.google.com', 'google.com']
    },
    {
      name: 'Google',
      patterns: ['google', 'google account', 'google sign in'],
      officialDomains: ['google.com', 'accounts.google.com', 'google.co.in']
    },
    {
      name: 'Microsoft',
      patterns: ['microsoft', 'office 365', 'outlook', 'microsoft account'],
      officialDomains: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com']
    }
  ];

  /**
   * Inspects document title and headings against high-value institutions when sensitive inputs are present.
   * Emits brand spoof if host is not an official domain for that brand.
   *
   * @param {Document|HTMLElement} [domDocument] - DOM document
   * @param {string} [hostname=''] - Target hostname
   * @returns {{ detected: boolean, brand: string|null }}
   */
  function detectDomBrandSpoof(domDocument, hostname = '') {
    const doc = domDocument || (typeof document !== 'undefined' ? document : null);
    if (!doc) return { detected: false, brand: null };

    const currentHost = (hostname || (typeof location !== 'undefined' ? location.hostname : '') || '').toLowerCase().replace(/^www\./, '');
    if (!currentHost) return { detected: false, brand: null };

    // 1. Extract title and top headings (h1, h2)
    const title = (doc.title || '').toLowerCase();
    let headingText = '';
    try {
      const headings = doc.querySelectorAll ? doc.querySelectorAll('h1, h2') : [];
      for (let i = 0; i < headings.length; i++) {
        headingText += ' ' + (headings[i].innerText || headings[i].textContent || '');
      }
    } catch (_) {}
    const targetText = `${title} ${headingText}`.toLowerCase();

    // 2. Check for presence of input fields requesting credentials/sensitive data
    let hasSensitiveInput = false;
    try {
      const inputs = doc.querySelectorAll ? doc.querySelectorAll('input') : [];
      for (let i = 0; i < inputs.length; i++) {
        const inp = inputs[i];
        const type = (inp.type || '').toLowerCase();
        const attr = ((inp.name || '') + ' ' + (inp.id || '') + ' ' + (inp.placeholder || '') + ' ' + (inp.getAttribute ? inp.getAttribute('aria-label') || '' : '') + ' ' + (inp.className || '')).toLowerCase();
        if (type === 'password' || /password|passwd|otp|pin|mpin|cvv|card|account|mobile|phone/i.test(attr)) {
          hasSensitiveInput = true;
          break;
        }
      }
    } catch (_) {}

    if (!hasSensitiveInput) {
      return { detected: false, brand: null };
    }

    for (const brand of HIGH_VALUE_DOM_BRANDS) {
      const matchesBrand = brand.patterns.some(p => targetText.includes(p));
      if (matchesBrand) {
        const isOfficial = brand.officialDomains.some(d => currentHost === d || currentHost.endsWith('.' + d));
        if (!isOfficial) {
          return {
            detected: true,
            brand: brand.name
          };
        }
      }
    }

    return { detected: false, brand: null };
  }

  /**
   * Scans text and link URLs for Digital Arrest extortion and Malicious APK droppers.
   *
   * @param {string} pageText - Inner text or visible corpus
   * @param {string[]} [linkUrls=[]] - Array of anchor/download hrefs on the page
   * @returns {{ detected: boolean, signal?: string, type?: string, reason?: string, phrase?: string, filename?: string }}
   */
  function detectDigitalArrestAndApkScams(pageText = '', linkUrls = []) {
    const rawNormalized = normalizeEvasions(pageText);
    const text = (rawNormalized || '').toLowerCase();

    // 1. Digital Arrest Extortion Scan
    const hasEnforcementLure = LAW_ENFORCEMENT_LURES.some(l => text.includes(l));
    const hasExtortionDemand = EXTORTION_DEMAND_TERMS.some(d => text.includes(d));

    if (hasEnforcementLure && (hasExtortionDemand || text.includes('under digital arrest') || text.includes('virtual arrest') || text.includes('डिजिटल अरेस्ट') || text.includes('டிஜிட்டல் கைது'))) {
      const matchedLure = LAW_ENFORCEMENT_LURES.find(l => text.includes(l)) || 'digital arrest';
      return {
        detected: true,
        type: 'DIGITAL_ARREST',
        signal: 'SIG_DIGITAL_ARREST_EXTORTION',
        reason: `Digital Arrest extortion pattern detected impersonating law enforcement: "${matchedLure}"`,
        phrase: matchedLure
      };
    }

    // 2. Malicious Android APK Dropper Scan
    // Check link URLs
    const allLinks = Array.isArray(linkUrls) ? linkUrls : [];
    for (const rawLink of allLinks) {
      const link = (rawLink || '').toLowerCase();
      if (link.includes('.apk')) {
        const apkNameMatch = link.match(/([a-zA-Z0-9_\-.]+\.apk)/i);
        const apkName = apkNameMatch ? apkNameMatch[1] : 'unverified.apk';

        if (KNOWN_MALICIOUS_APKS.some(k => apkName.includes(k)) || APK_LURE_KEYWORDS.some(k => link.includes(k) || text.includes(k))) {
          return {
            detected: true,
            type: 'MALICIOUS_APK',
            signal: 'SIG_MALICIOUS_APK_DROPPER',
            reason: `Malicious Android APK dropper detected: "${apkName}"`,
            filename: apkName
          };
        }
      }
    }

    // Check raw pageText for APK references
    const textApkMatch = text.match(/\b([a-zA-Z0-9_\-.]+\.apk)\b/i);
    if (textApkMatch) {
      const apkName = textApkMatch[1];
      if (KNOWN_MALICIOUS_APKS.some(k => apkName.includes(k)) || APK_LURE_KEYWORDS.some(k => text.includes(k))) {
        return {
          detected: true,
          type: 'MALICIOUS_APK',
          signal: 'SIG_MALICIOUS_APK_DROPPER',
          reason: `Malicious Android APK dropper referenced on page: "${apkName}"`,
          filename: apkName
        };
      }
    }

    return { detected: false };
  }

  /**
   * Scans document for deceptive UPI QR code collect traps masquerading as received money.
   *
   * @param {Document|HTMLElement} [domDocument] - DOM document or element tree
   * @returns {{ detected: boolean, signal?: string, reason?: string, upiUri?: string, lurePhrase?: string }}
   */
  function detectUpiQrCollectTrap(domDocument) {
    const doc = domDocument || (typeof document !== 'undefined' ? document : null);
    if (!doc) return { detected: false };

    let textCorpus = '';
    try {
      const rawText = doc.body ? doc.body.innerText || doc.body.textContent || '' : '';
      textCorpus = normalizeEvasions(rawText).toLowerCase();
    } catch (_) {
      textCorpus = '';
    }

    // Check for honest checkout context (Stripe, Razorpay, PayU, standard e-commerce)
    let currentUrl = '';
    try {
      currentUrl = doc.location?.href || (typeof window !== 'undefined' ? window.location?.href : '') || '';
    } catch (_) {}

    if (currentUrl && (isAuthorizedPaymentGatewayOrMerchant(currentUrl) || isLegitimateCheckoutFlow(currentUrl, textCorpus))) {
      const matchedLure = DECEPTIVE_RECEIVE_LURES.find(lure => textCorpus.includes(lure));
      if (!matchedLure) {
        return { detected: false };
      }
    }

    const honestCheckoutPhrases = [
      'authorize payment',
      'scan this qr code using your preferred upi app',
      'scan this qr code with your upi app',
      'powered by stripe',
      'powered by razorpay',
      'powered by payu',
      'powered by billdesk',
      'billing address',
      'order summary',
      'total due',
      'subscribe',
      'checkout',
      'to pay for your order',
      'pay for your order',
      'upi is supported in multiple apps'
    ];
    const hasHonestCheckout = honestCheckoutPhrases.some(phrase => textCorpus.includes(phrase));
    if (hasHonestCheckout) {
      return { detected: false };
    }

    // Check for deceptive receive-money lures
    const matchedLure = DECEPTIVE_RECEIVE_LURES.find(lure => textCorpus.includes(lure));
    if (!matchedLure) {
      return { detected: false };
    }

    // Look for UPI pay intent or QR code indicators
    let hasUpiIntent = false;
    let upiUri = '';

    // Check <a> links with upi://pay
    try {
      const upiLinks = doc.querySelectorAll ? doc.querySelectorAll('a[href^="upi://pay" i], [data-upi*="upi://pay" i]') : [];
      if (upiLinks && upiLinks.length > 0) {
        hasUpiIntent = true;
        upiUri = upiLinks[0].getAttribute('href') || upiLinks[0].getAttribute('data-upi') || '';
      }
    } catch (_) {}

    // Check QR code images or canvas
    let hasQrElement = false;
    try {
      const qrElements = doc.querySelectorAll ? doc.querySelectorAll('img[src*="qr" i], img[alt*="qr" i], img[alt*="upi" i], canvas, [class*="qr" i], [id*="qr" i]') : [];
      if (qrElements && qrElements.length > 0) {
        hasQrElement = true;
      }
    } catch (_) {}

    if (hasUpiIntent || hasQrElement || textCorpus.includes('upi://pay') || textCorpus.includes('qr scan') || textCorpus.includes('scan karo')) {
      const forensics = analyzeUpiIntentForensics(upiUri || 'upi://pay', textCorpus);
      return {
        detected: true,
        signal: 'SIG_UPI_QR_COLLECT_TRAP',
        reason: `Deceptive UPI QR collect trap detected pairing "${matchedLure}" with money deduction trigger.`,
        upiUri: upiUri || 'upi://pay',
        lurePhrase: matchedLure,
        forensicBreakdown: forensics.forensicBreakdown
      };
    }

    return { detected: false };
  }

  /**
   * Identifies Digital Arrest surveillance traps where an extortion page attempts to harvest
   * Webcam, Microphone, or Geolocation under the guise of fake legal/police authority.
   *
   * @param {string} pageText - Text content of the page or document
   * @param {string[]|object} [requestedPermissions=[]] - Requested surveillance permissions (camera, microphone, geolocation)
   * @param {string} [hostname=''] - Target hostname
   * @returns {{ detected: boolean, signal?: string, score?: number, verdict?: string, reason?: string, matchedLure?: string, requestedPermissions?: string[] }}
   */
  function detectDigitalArrestSurveillanceTrap(pageText = '', requestedPermissions = [], hostname = '') {
    const host = (hostname || (typeof location !== 'undefined' ? location.hostname : '') || '').toLowerCase().replace(/^www\./, '');
    const isGovDomain = host.endsWith('.gov.in') || host.endsWith('.nic.in') || host === 'gov.in' || host === 'nic.in';
    if (isGovDomain) {
      return { detected: false };
    }

    const rawNormalized = normalizeEvasions(pageText);
    const text = (rawNormalized || '').toLowerCase();

    // Check for law enforcement, court, arrest, KYC, customs keywords
    const SURVEILLANCE_LURES = [
      'digital arrest', 'cbi', 'police', 'supreme court', 'high court', 'courtroom', 'virtual court',
      'arrest warrant', 'customs', 'narcotics', 'ed notice', 'crime branch', 'money laundering',
      'kyc verification', 'rbi safe account', 'trai disconnection', 'cyber crime',
      'सीबीआई', 'डिजिटल अरेस्ट', 'पुलिस', 'वारंट', 'न्यायालय',
      'சிபிஐ', 'டிஜிட்டல் கைது', 'காவல்துறை', 'நீதிமன்றம்'
    ];

    const matchedLure = SURVEILLANCE_LURES.find(l => text.includes(l));
    if (!matchedLure) {
      return { detected: false };
    }

    // Normalize requestedPermissions
    let perms = [];
    if (Array.isArray(requestedPermissions)) {
      perms = requestedPermissions.map(p => String(p).toLowerCase());
    } else if (requestedPermissions && typeof requestedPermissions === 'object') {
      if (requestedPermissions.video) perms.push('camera');
      if (requestedPermissions.audio) perms.push('microphone');
      if (requestedPermissions.geolocation) perms.push('geolocation');
    }

    const hasSurveillanceRequest = perms.length === 0 || perms.some(p =>
      p.includes('cam') || p.includes('video') || p.includes('mic') || p.includes('audio') || p.includes('geo') || p.includes('loc')
    );

    if (hasSurveillanceRequest) {
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

  export {
    LAW_ENFORCEMENT_LURES,
    EXTORTION_DEMAND_TERMS,
    KNOWN_MALICIOUS_APKS,
    APK_LURE_KEYWORDS,
    DECEPTIVE_RECEIVE_LURES,
    HIGH_VALUE_DOM_BRANDS,
    normalizeEvasions,
    detectDomBrandSpoof,
    detectDigitalArrestAndApkScams,
    detectUpiQrCollectTrap,
    detectDigitalArrestSurveillanceTrap,
    analyzeUpiIntentForensics
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.LAW_ENFORCEMENT_LURES = LAW_ENFORCEMENT_LURES;
    globalThis.EXTORTION_DEMAND_TERMS = EXTORTION_DEMAND_TERMS;
    globalThis.KNOWN_MALICIOUS_APKS = KNOWN_MALICIOUS_APKS;
    globalThis.APK_LURE_KEYWORDS = APK_LURE_KEYWORDS;
    globalThis.DECEPTIVE_RECEIVE_LURES = DECEPTIVE_RECEIVE_LURES;
    globalThis.HIGH_VALUE_DOM_BRANDS = HIGH_VALUE_DOM_BRANDS;
    globalThis.normalizeEvasions = normalizeEvasions;
    globalThis.detectDomBrandSpoof = detectDomBrandSpoof;
    globalThis.detectDigitalArrestAndApkScams = detectDigitalArrestAndApkScams;
    globalThis.detectUpiQrCollectTrap = detectUpiQrCollectTrap;
    globalThis.detectDigitalArrestSurveillanceTrap = detectDigitalArrestSurveillanceTrap;
    globalThis.analyzeUpiIntentForensics = analyzeUpiIntentForensics;
    globalThis.BharatScamDetectors = {
      LAW_ENFORCEMENT_LURES,
      EXTORTION_DEMAND_TERMS,
      KNOWN_MALICIOUS_APKS,
      APK_LURE_KEYWORDS,
      DECEPTIVE_RECEIVE_LURES,
      HIGH_VALUE_DOM_BRANDS,
      normalizeEvasions,
      detectDomBrandSpoof,
      detectDigitalArrestAndApkScams,
      detectUpiQrCollectTrap,
      detectDigitalArrestSurveillanceTrap,
      analyzeUpiIntentForensics
    };
  }

  export default {
    LAW_ENFORCEMENT_LURES,
    EXTORTION_DEMAND_TERMS,
    KNOWN_MALICIOUS_APKS,
    APK_LURE_KEYWORDS,
    DECEPTIVE_RECEIVE_LURES,
    HIGH_VALUE_DOM_BRANDS,
    normalizeEvasions,
    detectDomBrandSpoof,
    detectDigitalArrestAndApkScams,
    detectUpiQrCollectTrap,
    detectDigitalArrestSurveillanceTrap,
    analyzeUpiIntentForensics
  };
