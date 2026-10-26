/**
 * shared/text-scanner.js — Pure, portable text & URL scanner for WhatsApp, SMS, and URLs
 *
 * Designed with zero browser extension APIs and zero DOM dependencies so it can be imported unchanged
 * into a mobile PWA, background service worker, or Node.js test runner.
 */

import {
  isIpBasedUrl,
  hasMissingHttps,
  hasExcessiveSubdomains,
  hasBrandNameInWrongDomain,
  hasSuspiciousUrlPattern,
  hasPunycodeOrKeywords,
  hasFinancialKeywordInHostname,
  hasBrandVariantMatch,
  hasMalvertisingPattern,
  hasRandomLookingHostname,
  hasAffiliateTrackerPattern,
  hasPiracyOrUnverifiedMediaPattern,
  hasAitmProxyUrlSignature,
  hasHomographAttack,
  isUrlShortener
} from '../background/rules.js';

import { detectTyposquatting } from '../background/brand-detector.js';
import { calculateRisk } from '../background/risk-engine.js';
import { detectDigitalArrestAndApkScams, normalizeEvasions } from '../content/bharat-scam-detectors.js';
import { analyzeUpiIntentForensics } from './upi-forensics.js';
import { analyzeRedirectChainForensics } from './redirect-forensics.js';
import { goldenRuleForSignal } from './citizen-messages.js';
import * as defaultPsl from './psl.js';
import { classifyTextWithSubwordAi } from './ai-nlp-classifier.js';
import { computeSecvIntentVector } from './secv-intent-engine.js';
import { createVerdict, createAbstentionVerdict } from './verdict-contract.js';

/**
 * Parses a upi://pay URI and inspects whether it represents a deceptive collect/deduct trap.
 *
 * @param {string} str - String containing a upi://pay URI or standalone upi URI
 * @param {string} [contextText=''] - Surrounding text context
 * @returns {null | { pa: string, pn: string, am: string, tn: string, isCollect: boolean, raw: string }}
 */
export function parseUpiString(str, contextText = '') {
  if (!str || typeof str !== 'string') return null;

  let rawUri = '';
  const trimmed = str.trim();
  if (/^upi:\/\/pay\?/i.test(trimmed)) {
    const lineEnd = trimmed.search(/[\r\n]/);
    rawUri = lineEnd !== -1 ? trimmed.slice(0, lineEnd) : trimmed;
  } else {
    const match = str.match(/upi:\/\/pay\?[^\r\n"'<>]+/i);
    if (!match) return null;
    rawUri = match[0];
  }
  try {
    const qIndex = rawUri.indexOf('?');
    const queryString = rawUri.slice(qIndex + 1);
    const params = new URLSearchParams(queryString);

    const pa = params.get('pa') || '';
    const pn = params.get('pn') || '';
    const am = params.get('am') || '';
    const tn = params.get('tn') || '';

    // Inspect transaction note, payee name, and surrounding context for receive/cashback lures
    const combinedContext = `${contextText} ${str} ${tn} ${pn}`.toLowerCase();
    const collectLureKeywords = [
      'cashback', 'refund', 'receive', 'olx', 'buyer', 'advance',
      'claim', 'bonus', 'prize', 'lottery', 'reward',
      'credit', 'credited', 'crediting', 'won', 'congratulations', 'gift',
      'रिफंड', 'कैशबैक', 'इनाम', 'पैसे प्राप्त', 'क्रेडिट', 'लॉटरी',
      'கேஷ்பேக்', 'பணம் பெற', 'பரிசு',
      'క్యాష్‌బ్యాక్', 'డబ్బు పొందండి', 'బహుమతి'
    ];

    const hasLure = collectLureKeywords.some(kw => combinedContext.includes(kw));

    const honestPhrases = [
      'authorize payment',
      'scan this qr code using your preferred upi app',
      'powered by stripe',
      'powered by razorpay',
      'billing address',
      'total due',
      'order summary',
      'pay ₹'
    ];
    const isHonestCheckout = honestPhrases.some(p => combinedContext.includes(p));
    const explicitDeceptiveLures = [
      'scan to receive',
      'receive cashback',
      'claim reward',
      'get refund',
      'prize money',
      'olx buyer',
      'money will be credited',
      'cashback won'
    ];
    const hasExplicitDeceptiveLure = explicitDeceptiveLures.some(l => combinedContext.includes(l));

    // Deterministic NPCI UPI protocol forensic audit
    const forensics = analyzeUpiIntentForensics(rawUri, `${contextText} ${str}`);
    // If an amount is specified and context promises money received/cashback or NPCI flags forensic trap
    const isCollect = (!isHonestCheckout || hasExplicitDeceptiveLure) && ((!!(am && hasLure)) || forensics.detected);

    return {
      pa,
      pn,
      am,
      tn,
      isCollect,
      raw: rawUri,
      forensicBreakdown: forensics.forensicBreakdown
    };
  } catch (_) {
    return null;
  }
}

/**
 * Extracts all URLs from a block of text, including full URLs with protocols,
 * bare domains (e.g. sbi-kyc-verify.top/x, bit.ly/123), and raw IP URLs.
 *
 * @param {string} text
 * @returns {string[]} Array of unique extracted URLs
 */
export function extractUrls(text) {
  if (!text || typeof text !== 'string') return [];
  const urls = new Set();

  // Helper to strip trailing sentence punctuation
  const cleanUrl = (raw) => {
    if (!raw) return '';
    return raw.replace(/[.,;:!?\)\]\}'"]+$/, '');
  };

  // 1. Full URLs with explicit protocol (http, https, ftp)
  const protoRegex = /\b(?:https?|ftp):\/\/[^\s"'<>)\]]+/gi;
  let match;
  while ((match = protoRegex.exec(text)) !== null) {
    const cleaned = cleanUrl(match[0]);
    if (cleaned && !cleaned.toLowerCase().startsWith('upi://')) {
      urls.add(cleaned);
    }
  }

  // 2. Bare domain names with common TLDs or URL shorteners
  const bareRegex = /\b(?:[a-zA-Z0-9-]+\.)+(?:com|in|co\.in|gov\.in|ac\.in|net|org|xyz|top|site|online|tech|info|click|sbs|cfd|icu|buzz|shop|fun|cc|pw|me|app|dev|io|biz|live|monster|tv|ly|co|club|vip|bank|sbi)(?::\d+)?(?:\/[^\s"'<>)\]]*)?/gi;
  while ((match = bareRegex.exec(text)) !== null) {
    const raw = match[0];
    const startIndex = match.index;
    const preceding = text.slice(Math.max(0, startIndex - 8), startIndex);
    if (!preceding.includes('://')) {
      const cleaned = cleanUrl(raw);
      if (cleaned) urls.add(cleaned);
    }
  }

  // 3. Raw IPv4 addresses with optional port and path
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?(?:\/[^\s"'<>)\]]*)?/g;
  while ((match = ipRegex.exec(text)) !== null) {
    const raw = match[0];
    const startIndex = match.index;
    const preceding = text.slice(Math.max(0, startIndex - 8), startIndex);
    if (!preceding.includes('://')) {
      const cleaned = cleanUrl(raw);
      if (cleaned) urls.add(cleaned);
    }
  }

  return Array.from(urls);
}

/**
 * Scans an arbitrary text input (pasted WhatsApp message, SMS, URL, or upi://pay string).
 *
 * @param {string} input - Text to inspect
 * @param {object} [options={}] - Options
 * @param {Array} [options.brandsList=[]] - Known brands list for typosquat & impersonation detection
 * @param {object} [options.psl] - Optional custom Public Suffix List implementation for PWA
 * @param {object} [options.domSignals] - Optional DOM signals
 * @returns {{
 *   verdict: 'safe' | 'caution' | 'danger',
 *   score: number,
 *   signals: Array<{ id: string, plainKey: string }>,
 *   extracted: {
 *     urls: string[],
 *     upi: null | { pa: string, pn: string, am: string, tn: string, isCollect: boolean },
 *     apkNames: string[]
 *   },
 *   goldenRuleKey: string
 * }}
 */
export function scanText(input, options = {}) {
  // Safe default output for empty or invalid input
  const defaultContract = createAbstentionVerdict('message', 'UNSUPPORTED_INPUT', 'No input provided for scanning.');
  const defaultResult = {
    verdict: 'safe',
    score: 0,
    signals: [],
    extracted: {
      urls: [],
      upi: null,
      apkNames: []
    },
    goldenRuleKey: 'generic',
    verdictContract: defaultContract
  };

  if (!input || typeof input !== 'string') {
    return defaultResult;
  }

  const rawText = input.trim();
  if (!rawText) {
    return defaultResult;
  }

  try {
    const brandsList = Array.isArray(options.brandsList) ? options.brandsList : [];
    const psl = options.psl || defaultPsl;

    const extractedUrls = extractUrls(rawText);
    const upiData = parseUpiString(rawText);
    const extractedApkNames = [];
    const signals = [];
    let maxScore = 0;

    const normalizedText = normalizeEvasions(rawText);
    const textLower = normalizedText.toLowerCase();

    // ── 1. Digital Arrest & Malicious APK Text Scans ──────────────────────────
    const bharatScam = detectDigitalArrestAndApkScams(normalizedText, extractedUrls);
    if (bharatScam && bharatScam.detected) {
      if (bharatScam.type === 'DIGITAL_ARREST') {
        const sigId = bharatScam.signal || 'SIG_DIGITAL_ARREST_EXTORTION';
        signals.push({ id: sigId, plainKey: sigId });
        maxScore = Math.max(maxScore, 85);
      } else if (bharatScam.type === 'MALICIOUS_APK') {
        const sigId = bharatScam.signal || 'SIG_MALICIOUS_APK_DROPPER';
        signals.push({ id: sigId, plainKey: sigId });
        if (bharatScam.filename && !extractedApkNames.some(n => n.toLowerCase() === bharatScam.filename.toLowerCase())) {
          extractedApkNames.push(bharatScam.filename);
        }
        maxScore = Math.max(maxScore, 90);
      }
    }

    // ── 2. Direct APK Link / Reference Extraction ────────────────────────────
    for (const urlStr of extractedUrls) {
      const apkMatch = urlStr.match(/([a-zA-Z0-9_\-.]+\.apk)/i);
      if (apkMatch) {
        const filename = apkMatch[1];
        if (!extractedApkNames.some(n => n.toLowerCase() === filename.toLowerCase())) {
          extractedApkNames.push(filename);
        }
        if (!signals.some(s => s.id === 'SIG_MALICIOUS_APK_DROPPER')) {
          signals.push({ id: 'SIG_MALICIOUS_APK_DROPPER', plainKey: 'SIG_MALICIOUS_APK_DROPPER' });
        }
        maxScore = Math.max(maxScore, 90);
      }
    }

    // ── 3. Deceptive UPI QR / Collect Trap (including Hinglish/Tanglish phrases) ─
    const qrColloquialRegex = /\b(?:qr scan karo|scan karke paise|scan karo.*paise|scan.*paise milega|qr.*aayega|cashback milega|refund aayega|scan pannunga|scan panna paise|scan cheyandi)\b/i;
    const upiForensics = analyzeUpiIntentForensics(rawText, rawText);
    const honestCheckoutPhrases = [
      'authorize payment',
      'scan this qr code using your preferred upi app',
      'powered by stripe',
      'powered by razorpay',
      'billing address',
      'total due',
      'order summary',
      'pay ₹'
    ];
    const hasHonestCheckoutInText = honestCheckoutPhrases.some(phrase => textLower.includes(phrase));
    const explicitDeceptiveLuresInText = [
      'scan to receive',
      'receive cashback',
      'claim reward',
      'get refund',
      'prize money',
      'olx buyer',
      'money will be credited'
    ].some(l => textLower.includes(l));
    const isSuppressedByHonestCheckout = hasHonestCheckoutInText && !explicitDeceptiveLuresInText;

    if (!isSuppressedByHonestCheckout && ((upiData && upiData.isCollect) || qrColloquialRegex.test(normalizedText) || qrColloquialRegex.test(rawText))) {
      if (!signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP')) {
        signals.push({ id: 'SIG_UPI_QR_COLLECT_TRAP', plainKey: 'SIG_UPI_QR_COLLECT_TRAP' });
      }
      maxScore = Math.max(maxScore, 85);
    }
    if (!isSuppressedByHonestCheckout && upiForensics && upiForensics.detected) {
      if (!signals.some(s => s.id === 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC')) {
        signals.unshift({ id: 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC', plainKey: 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC' });
      }
      maxScore = Math.max(maxScore, 90);
    }

    // ── 3b. Illegal In-Browser / Message UPI PIN Collection Scan ─────────────
    // Catches English, Devanagari, Tamil, Telugu, and Romanized Hinglish/Tanglish PIN prompts
    const pinLureRegex = /(?:upi|mpin|atm|4-digit|6-digit|4 digit|6 digit)?\s*(?:pin|पिन|பின்|పిన్).*(?:enter|type|input|provide|submit|fill|verify|receive|credit|cashback|refund|money|claim|dalo|daalo|daal|daaliye|potu|podu|दर्ज|உள்ளிட|నమోదు|ரசீது|रिफंड|milega|aayega)|(?:enter|type|input|provide|submit|fill|verify|dalo|daalo|daal|daaliye|potu|podu|दर्ज|உள்ளிட|నమోదు).*(?:upi|mpin|atm)?\s*(?:pin|पिन|பின்|పిన్)|\b(?:pin daalo|pin dalo|mpin dalo|upi pin daal|upi pin dalo|pin podu|pin potu)\b/i;
    if (pinLureRegex.test(normalizedText) || pinLureRegex.test(rawText)) {
      if (!signals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION')) {
        signals.unshift({ id: 'SIG_ILLEGAL_WEB_PIN_COLLECTION', plainKey: 'SIG_ILLEGAL_WEB_PIN_COLLECTION' });
      }
      maxScore = Math.max(maxScore, 95);
    }

    // ── 3c. Electricity Bill Disconnection Extortion Scan ─────────────────────
    const utilityKeywords = ['electricity', 'power', 'bijli', 'bescom', 'tneb', 'msedcl', 'uppcl', 'dhbvn', 'uhbvn', 'wbsedcl', 'tssouthernpower', 'light bill', 'electricity officer', 'बिजली'];
    const hasUtilityMention = utilityKeywords.some(u => textLower.includes(u));

    const disconnectKeywords = [
      'disconnected', 'disconnect', 'power cut', 'cut tonight', 'disconnection',
      'unpaid bill', 'update bill', 'कट जाएगी', 'மின்சாரம் துண்டிக்கப்படும்', 'కరెంట్ కట్'
    ];
    const hasDisconnectUrgency = disconnectKeywords.some(d => textLower.includes(d)) ||
      (textLower.includes('tonight') && (textLower.includes('bill') || textLower.includes('power') || textLower.includes('officer'))) ||
      (hasUtilityMention && textLower.includes('immediately'));

    if (hasUtilityMention && hasDisconnectUrgency) {
      if (!signals.some(s => s.id === 'SIG_UTILITY_BILL_EXTORTION')) {
        signals.push({ id: 'SIG_UTILITY_BILL_EXTORTION', plainKey: 'SIG_UTILITY_BILL_EXTORTION' });
      }
      maxScore = Math.max(maxScore, 85);
    }

    // ── 3d. IndiaPost / Courier Parcel Delivery Smishing Scan ────────────────
    const courierKeywords = ['indiapost', 'india post', 'bharatiya dak', 'भारतीय डाक', 'delhivery', 'bluedart', 'dtdc', 'speed post', 'courier', 'parcel', 'package'];
    const hasCourierMention = courierKeywords.some(c => textLower.includes(c));

    const parcelHoldKeywords = [
      'arrived at warehouse', 'warehouse', 'incomplete address', 'address update', 'update address',
      'delivery failed', 'delivery attempt failed', 'unable to deliver', 'within 12 hours',
      'within 24 hours', 'held at customs', 'held due to address', 'confirm address', 'delivery fee'
    ];
    const hasParcelHold = parcelHoldKeywords.some(p => textLower.includes(p));

    if (hasCourierMention && hasParcelHold) {
      if (!signals.some(s => s.id === 'SIG_FAKE_PARCEL_DELIVERY_LURE')) {
        signals.push({ id: 'SIG_FAKE_PARCEL_DELIVERY_LURE', plainKey: 'SIG_FAKE_PARCEL_DELIVERY_LURE' });
      }
      maxScore = Math.max(maxScore, 80);
    }

    // ── 3e. 5D Psycholinguistic Coercion & Intent Vector Engine ──────────────
    const secv = computeSecvIntentVector(rawText);
    if (secv && secv.isConvergentScam) {
      if (!signals.some(s => s.id === 'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE')) {
        signals.push({
          id: 'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE',
          plainKey: 'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE',
          dominantAxis: secv.dominantAxis,
          score: secv.score,
          probability: secv.probability,
          evidence: secv.evidence,
          vector: secv.vector
        });
      }
      maxScore = Math.max(maxScore, Math.max(85, secv.score));
    }

    // ── 3f. Subword N-Gram Bayesian NLP Continuous Inference ─────────────────
    // Bypass conversational text NLP when the input is purely a raw protocol URI (e.g., upi://pay?...)
    const isPureProtocolUri = /^upi:\/\/pay\?/i.test(rawText.trim());
    const aiNlp = isPureProtocolUri
      ? { isScam: false, score: 0, scamProbability: 0, dominantClass: 'SAFE_CONVERSATION' }
      : classifyTextWithSubwordAi(rawText);
    // Coercion/extortion requires extraction action (E > 0) to constitute an actionable fraud trap
    const isCoercionWithoutExtraction = aiNlp.dominantClass === 'COERCION_EXTORTION' && secv && secv.vector.E === 0;
    if (aiNlp.isScam && aiNlp.scamProbability >= 0.78 && !isCoercionWithoutExtraction) {
      if (!signals.some(s => s.id === 'SIG_AI_NLP_SCAM_INTENT')) {
        signals.push({
          id: 'SIG_AI_NLP_SCAM_INTENT',
          plainKey: 'SIG_AI_NLP_SCAM_INTENT',
          dominantClass: aiNlp.dominantClass,
          scamProbability: aiNlp.scamProbability
        });
      }
      maxScore = Math.max(maxScore, Math.max(82, aiNlp.score));
    }

    // ── 4. URL Heuristics & Central Risk Engine Scoring ──────────────────────
    for (const rawUrl of extractedUrls) {
      const normalizedUrl = (rawUrl.startsWith('http://') || rawUrl.startsWith('https://'))
        ? rawUrl
        : `https://${rawUrl}`;

      let urlHostname = '';
      try {
        urlHostname = new URL(normalizedUrl).hostname.toLowerCase().replace(/^www\./, '');
      } catch (_) {
        urlHostname = normalizedUrl.split('/')[0].split(':')[0].toLowerCase().replace(/^www\./, '');
      }

      // Check for URL shorteners (bit.ly, tinyurl.com, etc.)
      const isShortener = isUrlShortener(urlHostname);
      if (isShortener) {
        const scamContextWords = [
          'kyc', 'pan', 'aadhaar', 'aadhar', 'bank', 'sbi', 'hdfc', 'icici', 'axis', 'pnb', 'kotak',
          'yono', 'netbanking', 'account', 'block', 'suspend', 'verify', 'update', 'otp', 'pin',
          'electricity', 'power', 'bill', 'bescom', 'tneb', 'msedcl', 'uppcl', 'disconnected',
          'parcel', 'courier', 'delivery', 'indiapost', 'dak', 'package', 'warehouse', 'address',
          'lottery', 'winner', 'won', 'prize', 'reward', 'cashback', 'bonus', 'crore', 'lakh', 'congratulations'
        ];
        const hasScamContext = scamContextWords.some(w => textLower.includes(w) || normalizedUrl.toLowerCase().includes(w));

        if (hasScamContext) {
          if (!signals.some(s => s.id === 'SIG_DECEPTIVE_SHORTENER_LURE')) {
            signals.push({ id: 'SIG_DECEPTIVE_SHORTENER_LURE', plainKey: 'SIG_DECEPTIVE_SHORTENER_LURE' });
          }
          maxScore = Math.max(maxScore, 80);
        } else {
          if (!signals.some(s => s.id === 'SIG_URL_SHORTENER_CAUTION')) {
            signals.push({ id: 'SIG_URL_SHORTENER_CAUTION', plainKey: 'SIG_URL_SHORTENER_CAUTION' });
          }
          maxScore = Math.max(maxScore, 45); // Caution verdict
        }
      }

      const ruleSignals = [
        isIpBasedUrl(normalizedUrl),
        hasMissingHttps(normalizedUrl),
        hasExcessiveSubdomains(normalizedUrl),
        hasBrandNameInWrongDomain(normalizedUrl, brandsList),
        hasSuspiciousUrlPattern(normalizedUrl),
        hasPunycodeOrKeywords(normalizedUrl),
        detectTyposquatting(normalizedUrl, brandsList),
        hasFinancialKeywordInHostname(normalizedUrl, brandsList),
        hasBrandVariantMatch(normalizedUrl, brandsList),
        hasMalvertisingPattern(normalizedUrl),
        hasRandomLookingHostname(normalizedUrl),
        hasAffiliateTrackerPattern(normalizedUrl),
        hasPiracyOrUnverifiedMediaPattern(normalizedUrl),
        hasAitmProxyUrlSignature(normalizedUrl),
        hasHomographAttack(normalizedUrl, brandsList)
      ];

      // Contextual KYC & Bank Scams Detection from message text or URL
      const urlLower = normalizedUrl.toLowerCase();
      const hasKycKeyword = urlLower.includes('kyc') || textLower.includes('kyc') ||
                            urlLower.includes('pan') || textLower.includes('pan') ||
                            urlLower.includes('aadhaar') || textLower.includes('aadhaar') ||
                            urlLower.includes('aadhar') || textLower.includes('aadhar');

      const hasBankOrUrgency = urlLower.includes('sbi') || textLower.includes('sbi') ||
                               urlLower.includes('hdfc') || textLower.includes('hdfc') ||
                               urlLower.includes('icici') || textLower.includes('icici') ||
                               urlLower.includes('axis') || textLower.includes('axis') ||
                               urlLower.includes('bank') || textLower.includes('bank') ||
                               textLower.includes('block') || textLower.includes('suspend') ||
                               textLower.includes('verify') || textLower.includes('update');

      let domSignals = options.domSignals || null;
      if (hasKycKeyword && hasBankOrUrgency && !domSignals) {
        domSignals = {
          kycCyberFraud: true,
          kycCyberFraudReason: 'Fake KYC / Bank update lure',
          hasCredentialCollection: true
        };
      }

      const hasAuthSub = ['login.', 'signin.', 'auth.', 'secure.', 'banking.', 'account.', 'verify.'].some(p => {
        try { return new URL(normalizedUrl).hostname.toLowerCase().startsWith(p); } catch (_) { return false; }
      });
      const hasAuthPathEndpoint = ['/auth', '/login', '/signin', '/portal', '/verification', '/logon'].some(p => urlLower.includes(p)) && (urlLower.endsWith('.php') || urlLower.endsWith('.aspx') || urlLower.includes('/auth/') || urlLower.includes('/login'));
      const hasBrandImpersonationRule = ruleSignals.some(s => s.id === 'RULE_BRAND_NAME_WRONG_DOMAIN' || s.id === 'RULE_BRAND_VARIANT_MATCH');

      if ((hasAuthSub && hasAuthPathEndpoint) || (hasBrandImpersonationRule && (hasAuthSub || hasAuthPathEndpoint))) {
        if (!domSignals) {
          domSignals = {
            hasCredentialCollection: true,
            hasPasswordInput: true,
            loginFormCount: 1,
            pageTitle: 'Sign In'
          };
        }
      }

      const verdict = calculateRisk(
        normalizedUrl,
        ruleSignals,
        null,
        domSignals,
        null,
        null,
        null,
        null,
        1.0,
        brandsList
      );

      const urlRiskScore = verdict.score || 0;
      maxScore = Math.max(maxScore, urlRiskScore);

      if (verdict.signals && Array.isArray(verdict.signals)) {
        for (const sig of verdict.signals) {
          if (sig.score > 0 && !signals.some(s => s.id === sig.id)) {
            signals.push({ id: sig.id, plainKey: sig.id });
          }
        }
      }
    }

    // ── 5. Verdict Thresholds (0-34: safe, 35-69: caution, 70-100: danger) ──
    const finalScore = Math.min(Math.max(maxScore, 0), 100);

    let verdict = 'safe';
    if (finalScore >= 70) {
      verdict = 'danger';
    } else if (finalScore >= 35) {
      verdict = 'caution';
    }

    // ── 6. Select Relevant Golden Rule ───────────────────────────────────────
    let goldenRuleKey = 'generic';
    if (signals.length > 0) {
      const priorityOrder = [
        'SIG_DIGITAL_ARREST_EXTORTION',
        'SIG_MALICIOUS_APK_DROPPER',
        'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC',
        'SIG_UPI_QR_COLLECT_TRAP',
        'SIG_ILLEGAL_WEB_PIN_COLLECTION',
        'SIG_UTILITY_BILL_EXTORTION',
        'SIG_FAKE_PARCEL_DELIVERY_LURE',
        'SIG_DECEPTIVE_SHORTENER_LURE',
        'SIG_KYC_CYBER_FRAUD',
        'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE',
        'SIG_FREE_HOST_CREDENTIAL_PHISH',
        'SIG_DOM_BRAND_IMPERSONATION',
        'SIG_AUTONOMOUS_BRAND_IDENTITY_MISMATCH',
        'SIG_AITM_REVERSE_PROXY_PHISH',
        'RULE_BRAND_NAME_WRONG_DOMAIN',
        'SIG_TYPOSQUATTING',
        'SIG_HOMOGRAPH_ATTACK',
        'SIG_URL_SHORTENER_CAUTION'
      ];
      const matchedSignal = priorityOrder.find(id => signals.some(s => s.id === id));
      if (matchedSignal === 'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE') {
        const secvSig = signals.find(s => s.id === 'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE');
        if (secvSig && (secvSig.dominantAxis === 'authority' || secvSig.dominantAxis === 'catastrophic_threat')) {
          goldenRuleKey = 'digital_arrest';
        } else {
          goldenRuleKey = 'otp_password';
        }
      } else {
        const sigId = matchedSignal || (signals[0] && signals[0].id) || signals[0];
        goldenRuleKey = goldenRuleForSignal(sigId);
      }
    }

    const modality = extractedUrls.length > 0 ? 'url' : (upiData ? 'payment_intent' : 'message');
    let threatCategory = 'unsupported_or_unknown';
    let isInsufficientEvidence = false;

    if (signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP' || s.id === 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC')) {
      threatCategory = 'upi_collect_payment_deception';
    } else if (signals.some(s => s.id === 'SIG_DIGITAL_ARREST_EXTORTION' || s.id === 'SIG_SURVEILLANCE_CAMERA_TRAP')) {
      threatCategory = 'digital_arrest_extortion';
    } else if (signals.some(s => s.id === 'SIG_MALICIOUS_APK_DROPPER')) {
      threatCategory = 'malicious_application_dropper';
    } else if (signals.some(s => s.id === 'SIG_KYC_CYBER_FRAUD')) {
      threatCategory = 'fake_kyc_account_blocking';
    } else if (signals.some(s => s.id === 'SIG_DOM_BRAND_IMPERSONATION' || s.id === 'RULE_BRAND_NAME_WRONG_DOMAIN')) {
      threatCategory = 'brand_impersonation';
    } else if (finalScore <= 20) {
      if (extractedUrls.length > 0 || upiData) {
        threatCategory = 'benign_legitimate_interaction';
      } else {
        const wordCount = rawText.split(/\s+/).filter(Boolean).length;
        if (wordCount < 4 || rawText.length < 25) {
          isInsufficientEvidence = true;
          threatCategory = 'unsupported_or_unknown';
        } else {
          threatCategory = 'benign_legitimate_interaction';
        }
      }
    }

    const riskClassification = isInsufficientEvidence
      ? 'ABSTAIN'
      : (finalScore >= 70 ? 'HIGH_RISK' : (finalScore >= 35 ? 'CAUTION' : 'SAFE'));

    const verdictContract = isInsufficientEvidence
      ? createAbstentionVerdict(
          modality,
          'INSUFFICIENT_EVIDENCE',
          'Input text contains no verifiable links, payment handles, or forensic markers to assess safety.'
        )
      : createVerdict({
          inputModality: modality,
          threatCategory,
          riskClassification,
          riskScore: finalScore,
          evidence: signals,
          humanExplanations: signals.map(s => s.id).filter(Boolean),
          recommendedAction: {
            safeNextStep: finalScore >= 70
              ? 'Do not approve this request, enter passwords, or install downloads.'
              : (finalScore >= 35
                ? 'Exercise caution. Verify with known official contacts.'
                : 'No overt threat detected in scanned text.'),
            recoveryRoute: threatCategory !== 'benign_legitimate_interaction' ? threatCategory : null,
            emergencyHelpline: '1930'
          },
          privacyDisclosure: {
            localOnly: true,
            externalLookups: [],
            redactionsApplied: []
          },
          knownLimitations: [
            'Pure on-device scan evaluates observable keywords, regular expressions, and heuristics.',
            'Conversational social engineering without financial demands may not trigger automated thresholds.'
          ]
        });

    return {
      verdict,
      score: finalScore,
      signals,
      extracted: {
        urls: extractedUrls,
        upi: upiData || (upiForensics && upiForensics.payeeVpa ? {
          pa: upiForensics.payeeVpa,
          pn: upiForensics.payeeName,
          am: String(upiForensics.debitAmount),
          tn: '',
          isCollect: upiForensics.detected,
          raw: rawText.match(/upi:\/\/pay\?[^\s"'<>]+/i)?.[0] || '',
          forensicBreakdown: upiForensics.forensicBreakdown
        } : null),
        apkNames: extractedApkNames
      },
      aiNlp,
      secv,
      goldenRuleKey,
      verdictContract
    };
  } catch (_) {
    return defaultResult;
  }
}

/**
 * Unrolls and simulates a multi-hop URL redirect chain or shortened redirect sequence.
 * Returns a hop-by-hop visual trace with status codes and flags hidden final destinations.
 *
 * @param {string|string[]|Array<{url: string, timestamp?: number, isTabHidden?: boolean, status?: string}>} inputUrlOrChain
 * @returns {{
 *   hops: Array<{ hop: number, url: string, status: string, hostname: string, domain: string, isShortener: boolean, isRotatorTld: boolean, isSuspicious: boolean }>,
 *   finalUrl: string,
 *   chainLength: number,
 *   forensics: object,
 *   signals: string[],
 *   verdict: { score: number, severity: string, state: string, reasons: string[] }
 * }}
 */
export function unrollRedirectChainSimulation(inputUrlOrChain) {
  let rawList = [];
  if (Array.isArray(inputUrlOrChain)) {
    rawList = inputUrlOrChain;
  } else if (typeof inputUrlOrChain === 'string') {
    const text = inputUrlOrChain.trim();
    // Check if string contains multiple URLs separated by newlines, arrows, or spaces
    const parts = text.split(/(?:\s*(?:->|=>|>|\||\n|\r)\s*|\s{2,})/).map(s => s.trim()).filter(Boolean);
    if (parts.length > 1) {
      rawList = parts;
    } else {
      // Check if text has embedded redirect query params like ?dest=, ?url=, ?redirect=, ?r=, ?target=
      const extracted = extractUrls(text);
      if (extracted.length > 0) {
        const rootUrl = extracted[0];
        rawList = [rootUrl];
        try {
          const u = new URL(rootUrl);
          const redirectParam = ['url', 'dest', 'destination', 'redirect', 'target', 'link', 'r', 'to'].find(p => u.searchParams.has(p));
          if (redirectParam) {
            const destVal = u.searchParams.get(redirectParam);
            if (destVal && (destVal.startsWith('http://') || destVal.startsWith('https://'))) {
              rawList.push(destVal);
            }
          }
        } catch (_) {}
      } else {
        rawList = [text];
      }
    }
  }

  const ROTATOR_TLDS = ['.xyz', '.top', '.click', '.sbs', '.cfd', '.icu', '.buzz', '.monster', '.live', '.fun', '.cam'];

  const normalizedChain = rawList.map((item, idx) => {
    const urlStr = typeof item === 'string' ? item : (item?.url || '');
    const timestamp = typeof item?.timestamp === 'number' ? item.timestamp : Date.now() + idx * 250;
    const isTabHidden = !!item?.isTabHidden;
    const customStatus = item?.status || '';
    return { url: urlStr, timestamp, isTabHidden, customStatus };
  }).filter(h => !!h.url);

  const hops = normalizedChain.map((hop, idx) => {
    let hostname = '';
    let domain = '';
    try {
      hostname = new URL(hop.url).hostname.toLowerCase();
      domain = defaultPsl.getDomain(hostname) || hostname;
    } catch (_) {}

    const isLast = idx === normalizedChain.length - 1;
    const isShort = isUrlShortener(hop.url);
    const isRotator = ROTATOR_TLDS.some(tld => hostname.endsWith(tld));
    const isSusp = isRotator || isShort || hostname.includes('rotator') || hop.url.includes('clickid=') || hop.url.includes('subid=');

    let status = hop.customStatus;
    if (!status) {
      if (isLast) {
        status = '200 OK';
      } else if (isShort) {
        status = '301 Moved Permanently';
      } else {
        status = '302 Found';
      }
    }

    return {
      hop: idx + 1,
      url: hop.url,
      status,
      hostname,
      domain,
      isShortener: isShort,
      isRotatorTld: isRotator,
      isSuspicious: isSusp,
      isTabHidden: hop.isTabHidden,
      timestamp: hop.timestamp
    };
  });

  const finalUrl = hops.length > 0 ? hops[hops.length - 1].url : '';
  const forensics = analyzeRedirectChainForensics(hops);

  // Scan final destination with text-scanner
  let scanRes = null;
  if (finalUrl) {
    scanRes = scanText(finalUrl);
  }

  const allSignals = new Set(forensics.signals);
  if (scanRes && scanRes.signals) {
    scanRes.signals.forEach(s => allSignals.add(s.id || s));
  }

  const signalsList = Array.from(allSignals);

  let finalScore = scanRes ? scanRes.score : 0;
  if (forensics.signals.includes('SIG_MALVERTISING_REDIRECT_CHAIN')) {
    finalScore = Math.max(finalScore, 80);
  }
  if (forensics.signals.includes('SIG_TAB_UNDER_HIJACK')) {
    finalScore = Math.max(finalScore, 85);
  }

  let severity = 'safe';
  let state = 'safe';
  if (finalScore >= 70) {
    severity = 'danger';
    state = 'danger';
  } else if (finalScore >= 35) {
    severity = 'caution';
    state = 'caution';
  }

  const reasons = [];
  if (forensics.hasRapidMultiHop) {
    reasons.push(`Rapid multi-hop redirect velocity (${forensics.uniqueRootDomains} root domains)`);
  }
  if (forensics.hasTldTurbulence) {
    reasons.push('Traverses high-risk rotator TLDs');
  }
  if (forensics.hasAdRotatorQuery) {
    reasons.push('Intermediate hops contain ad-rotator bridge parameters');
  }
  if (forensics.hasTabUnderSwap) {
    reasons.push('Tab-under background swap detected');
  }
  if (scanRes && scanRes.verdict && scanRes.verdict.reasons) {
    scanRes.verdict.reasons.forEach(r => {
      if (!reasons.includes(r)) reasons.push(r);
    });
  }

  return {
    hops,
    finalUrl,
    chainLength: hops.length,
    forensics,
    signals: signalsList,
    verdict: {
      score: finalScore,
      severity,
      state,
      reasons
    }
  };
}

export {
  scanText as scanTextForScams,
  isUrlShortener,
  normalizeEvasions,
  analyzeUpiIntentForensics,
  classifyTextWithSubwordAi
};

export default {
  scanText,
  parseUpiString,
  extractUrls,
  isUrlShortener,
  normalizeEvasions,
  analyzeUpiIntentForensics,
  unrollRedirectChainSimulation,
  classifyTextWithSubwordAi
};
