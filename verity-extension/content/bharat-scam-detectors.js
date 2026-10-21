/**
 * content/bharat-scam-detectors.js — Real-Time "Digital Arrest", Fake APK & QR "Quishing" Detectors
 *
 * Specialised threat intelligence detectors for Indian cyber fraud patterns:
 * 1. Digital Arrest Extortion (CBI/ED/Police video call extortion)
 * 2. Malicious Android APK Droppers (RTO Challan, PM Kisan, Wedding Card APKs)
 * 3. UPI QR Code Collect Traps (Fake cashback/refund QR scams)
 */

'use strict';

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
    'narcotics control bureau notice'
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
    'virtual court'
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
    'receive payment',
    'accept payment',
    'claim bonus',
    'scan qr to get money',
    'scan to credit',
    'scan & receive',
    'claim your refund',
    'instant refund',
    'cashback won',
    'scan code to accept'
  ];

  /**
   * Scans text and link URLs for Digital Arrest extortion and Malicious APK droppers.
   *
   * @param {string} pageText - Inner text or visible corpus
   * @param {string[]} [linkUrls=[]] - Array of anchor/download hrefs on the page
   * @returns {{ detected: boolean, signal?: string, type?: string, reason?: string, phrase?: string, filename?: string }}
   */
  function detectDigitalArrestAndApkScams(pageText = '', linkUrls = []) {
    const text = (pageText || '').toLowerCase();

    // 1. Digital Arrest Extortion Scan
    const hasEnforcementLure = LAW_ENFORCEMENT_LURES.some(l => text.includes(l));
    const hasExtortionDemand = EXTORTION_DEMAND_TERMS.some(d => text.includes(d));

    if (hasEnforcementLure && (hasExtortionDemand || text.includes('under digital arrest') || text.includes('virtual arrest'))) {
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
      textCorpus = (doc.body ? doc.body.innerText || doc.body.textContent || '' : '').toLowerCase();
    } catch (_) {
      textCorpus = '';
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

    if (hasUpiIntent || hasQrElement || textCorpus.includes('upi://pay')) {
      return {
        detected: true,
        signal: 'SIG_UPI_QR_COLLECT_TRAP',
        reason: `Deceptive UPI QR collect trap detected pairing "${matchedLure}" with money deduction trigger.`,
        upiUri: upiUri || 'upi://pay',
        lurePhrase: matchedLure
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
    detectDigitalArrestAndApkScams,
    detectUpiQrCollectTrap
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.LAW_ENFORCEMENT_LURES = LAW_ENFORCEMENT_LURES;
    globalThis.EXTORTION_DEMAND_TERMS = EXTORTION_DEMAND_TERMS;
    globalThis.KNOWN_MALICIOUS_APKS = KNOWN_MALICIOUS_APKS;
    globalThis.APK_LURE_KEYWORDS = APK_LURE_KEYWORDS;
    globalThis.DECEPTIVE_RECEIVE_LURES = DECEPTIVE_RECEIVE_LURES;
    globalThis.detectDigitalArrestAndApkScams = detectDigitalArrestAndApkScams;
    globalThis.detectUpiQrCollectTrap = detectUpiQrCollectTrap;
    globalThis.BharatScamDetectors = {
      LAW_ENFORCEMENT_LURES,
      EXTORTION_DEMAND_TERMS,
      KNOWN_MALICIOUS_APKS,
      APK_LURE_KEYWORDS,
      DECEPTIVE_RECEIVE_LURES,
      detectDigitalArrestAndApkScams,
      detectUpiQrCollectTrap
    };
  }

  export default {
    LAW_ENFORCEMENT_LURES,
    EXTORTION_DEMAND_TERMS,
    KNOWN_MALICIOUS_APKS,
    APK_LURE_KEYWORDS,
    DECEPTIVE_RECEIVE_LURES,
    detectDigitalArrestAndApkScams,
    detectUpiQrCollectTrap
  };
