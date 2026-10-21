import test from 'node:test';
import assert from 'node:assert/strict';

import {
  getVernacularAdvisory,
  speakVernacularAdvisory,
  HELPLINE_NUMBER,
  NATIONAL_PORTAL,
  SUPPORTED_LANGS
} from '../shared/vernacular-coach.js';

import {
  redactSensitiveCitizenData,
  buildForensicDossier
} from '../background/forensic-reporter.js';

import {
  detectDigitalArrestAndApkScams,
  detectUpiQrCollectTrap
} from '../content/bharat-scam-detectors.js';

import {
  generateXRayTeachingCards,
  parseUrlAnatomy,
  detectPsychologicalTrigger,
  generateContextualQuiz
} from '../shared/xray-educator.js';

import { calculateRisk } from '../background/risk-engine.js';
import { MESSAGES, SIGNAL_CATEGORY_MAP } from '../shared/messages.js';

// ════════════════════════════════════════════════════════════════════════════════
// 1. Vernacular Voice AI & Plain-Language Cyber Literacy Coach
// ════════════════════════════════════════════════════════════════════════════════

test('Vernacular Coach: provides advisories in all 4 supported Indian languages', () => {
  assert.equal(HELPLINE_NUMBER, '1930');
  assert.equal(NATIONAL_PORTAL, 'cybercrime.gov.in');
  assert.deepEqual(SUPPORTED_LANGS, ['en-IN', 'hi-IN', 'ta-IN', 'te-IN']);

  for (const lang of SUPPORTED_LANGS) {
    const adv = getVernacularAdvisory('SIG_DIGITAL_ARREST_EXTORTION', lang);
    assert.ok(adv.title, `Missing title for lang ${lang}`);
    assert.ok(adv.explanation, `Missing explanation for lang ${lang}`);
    assert.ok(adv.goldenRule, `Missing goldenRule for lang ${lang}`);
    assert.equal(adv.helpline, '1930');
    assert.equal(adv.lang, lang);
    assert.equal(adv.portal, 'cybercrime.gov.in');
  }
});

test('Vernacular Coach: covers all high-priority cyber-fraud threat signals', () => {
  const targetSignals = [
    'SIG_ILLEGAL_WEB_PIN_COLLECTION',
    'SIG_DIGITAL_ARREST_EXTORTION',
    'SIG_PHISHING_KIT_WEBHOOK_EXFIL',
    'SIG_CLICKFIX_CLIPBOARD_ATTACK',
    'SIG_UPI_QR_COLLECT_TRAP',
    'SIG_MALICIOUS_APK_DROPPER'
  ];

  for (const sig of targetSignals) {
    const enAdv = getVernacularAdvisory(sig, 'en-IN');
    const hiAdv = getVernacularAdvisory(sig, 'hi-IN');
    const taAdv = getVernacularAdvisory(sig, 'ta-IN');
    const teAdv = getVernacularAdvisory(sig, 'te-IN');

    assert.ok(enAdv.title.length > 5);
    assert.ok(hiAdv.title.length > 5);
    assert.ok(taAdv.title.length > 5);
    assert.ok(teAdv.title.length > 5);

    // Verify key vernacular semantics
    if (sig === 'SIG_ILLEGAL_WEB_PIN_COLLECTION') {
      assert.match(enAdv.explanation, /only used when you are sending money/i);
      assert.match(hiAdv.explanation, /पैसे भेजने/);
      assert.match(taAdv.explanation, /பணம் அனுப்புவதற்கு/);
      assert.match(teAdv.explanation, /డబ్బు పంపడానికి/);
    }

    if (sig === 'SIG_DIGITAL_ARREST_EXTORTION') {
      assert.match(enAdv.explanation, /never conduct "digital arrests"/i);
      assert.match(hiAdv.explanation, /डिजिटल अरेस्ट/);
      assert.match(taAdv.explanation, /டிஜிட்டல் கைது/);
      assert.match(teAdv.explanation, /డిజిటల్ అరెస్ట్/);
    }

    if (sig === 'SIG_UPI_QR_COLLECT_TRAP') {
      assert.match(enAdv.goldenRule, /never receives money/i);
      assert.match(hiAdv.goldenRule, /पैसे पाने के लिए कभी नहीं/);
    }
  }
});

test('Vernacular Coach: graceful fallback for unknown signal or locale', () => {
  const fallbackAdv = getVernacularAdvisory('UNKNOWN_CUSTOM_SIG', 'fr-FR');
  assert.equal(fallbackAdv.lang, 'en-IN');
  assert.equal(fallbackAdv.helpline, '1930');
  assert.match(fallbackAdv.title, /high-risk cyber threat blocked/i);
});

test('Vernacular Coach: speakVernacularAdvisory safe execution in Node.js and mock browser', () => {
  // In Node.js environment without Web Speech API
  const nodeResult = speakVernacularAdvisory('SIG_DIGITAL_ARREST_EXTORTION', 'hi-IN');
  assert.equal(nodeResult.spoken, false);
  assert.equal(nodeResult.reason, 'speech_synthesis_unavailable');
  assert.equal(nodeResult.lang, 'hi-IN');
  assert.ok(nodeResult.text.includes('डिजिटल अरेस्ट'));

  // Test with mock window.speechSynthesis
  let cancelCalled = false;
  let spokenUtterance = null;

  globalThis.window = {
    speechSynthesis: {
      cancel: () => { cancelCalled = true; },
      speak: (utt) => { spokenUtterance = utt; }
    },
    SpeechSynthesisUtterance: function (text) {
      this.text = text;
      this.lang = '';
      this.rate = 1.0;
      this.pitch = 1.0;
    }
  };

  const browserResult = speakVernacularAdvisory('SIG_UPI_QR_COLLECT_TRAP', 'en-IN');
  assert.equal(browserResult.spoken, true);
  assert.equal(cancelCalled, true);
  assert.ok(spokenUtterance);
  assert.equal(spokenUtterance.lang, 'en-IN');
  assert.equal(spokenUtterance.rate, 0.95);

  delete globalThis.window;
});

// ════════════════════════════════════════════════════════════════════════════════
// 2. Citizen PII Scrubbing & 1-Click 1930 / Chakshu Forensic Reporter
// ════════════════════════════════════════════════════════════════════════════════

test('Forensic Reporter: redactSensitiveCitizenData scrubs credentials and PII', () => {
  const rawScamUrl = 'https://fake-sbi.xyz/kyc?user=citizen99&password=MySecretPassword123&otp=839201&pin=4920&pan=ABCDE1234F&aadhaar=123456789012&token=jwt.eyJhbGciOi...';
  const sanitized = redactSensitiveCitizenData(rawScamUrl);

  assert.ok(!sanitized.includes('MySecretPassword123'), 'Password must be redacted');
  assert.ok(!sanitized.includes('839201'), 'OTP must be redacted');
  assert.ok(!sanitized.includes('4920'), 'PIN must be redacted');
  assert.ok(!sanitized.includes('ABCDE1234F'), 'PAN must be redacted');
  assert.ok(!sanitized.includes('123456789012'), 'Aadhaar must be redacted');
  assert.ok(sanitized.includes('user=citizen99'), 'Non-sensitive parameters must be preserved');
  assert.ok(sanitized.includes('[REDACTED_BY_VERITY]'));

  // Malformed or empty URL resilience
  assert.equal(redactSensitiveCitizenData(''), '');
  assert.equal(redactSensitiveCitizenData(null), '');
  const malformed = redactSensitiveCitizenData('http://bad:port#password=secret&pin=1234');
  assert.ok(!malformed.includes('secret'));
  assert.ok(!malformed.includes('1234'));
});

test('Forensic Reporter: buildForensicDossier extracts UPI VPAs and exfil webhooks', () => {
  const analysisResult = {
    score: 95,
    severity: 'CRITICAL / DANGER',
    reasons: [
      'Deceptive Indian Bank impersonation login form detected',
      'Exfiltration webhook communicating with rogue Telegram bot'
    ],
    signals: [
      { id: 'SIG_PHISHING_KIT_WEBHOOK_EXFIL' },
      { id: 'SIG_ILLEGAL_WEB_PIN_COLLECTION', params: { brand: 'State Bank of India' } }
    ]
  };

  const url = 'https://sbi-kyc-update.com/pay.php?pa=cyberfraudster@okhdfcbank&pin=9999';
  const metadata = {
    pageTitle: 'SBI Digital Customer Verification',
    pageText: 'Please send clearance fee to fraudulent.vpa@paytm or contact https://api.telegram.org/bot987654:XYZ-ABC12345_token/sendMessage and discord webhook https://discord.com/api/webhooks/123456789/tokenXYZ',
    hops: ['https://bit.ly/sbi-urgent', 'https://sbi-kyc-update.com']
  };

  const dossier = buildForensicDossier(analysisResult, url, metadata);

  assert.ok(dossier.incidentId.startsWith('VERITY-I4C-'));
  assert.ok(dossier.timestampIST.length > 5);
  assert.equal(dossier.suspectDomain, 'sbi-kyc-update.com');
  assert.equal(dossier.riskScore, 95);
  assert.equal(dossier.iocs.spoofedBrand, 'State Bank of India');

  // Verify extracted IOCs
  assert.ok(dossier.iocs.upiVpas.includes('cyberfraudster@okhdfcbank'));
  assert.ok(dossier.iocs.upiVpas.includes('fraudulent.vpa@paytm'));
  assert.ok(dossier.iocs.webhooks.includes('https://api.telegram.org/bot987654:XYZ-ABC12345_token/sendMessage'));
  assert.ok(dossier.iocs.webhooks.includes('https://discord.com/api/webhooks/123456789/tokenXYZ'));
  assert.deepEqual(dossier.iocs.redirectHops, ['https://bit.ly/sbi-urgent', 'https://sbi-kyc-update.com']);

  // Verify Official 1930 / Chakshu Incident Summary Text
  assert.ok(dossier.officialSummaryText.includes('NATIONAL CYBERCRIME REPORTING PORTAL (1930 / SANCHAR SAATHI CHAKSHU) DOSSIER'));
  assert.ok(dossier.officialSummaryText.includes(dossier.incidentId));
  assert.ok(dossier.officialSummaryText.includes('cyberfraudster@okhdfcbank'));
  assert.ok(dossier.officialSummaryText.includes('Sec 102 CrPC'));
  assert.ok(dossier.officialSummaryText.includes('Dial 1930 immediately'));

  // Ensure citizen credentials were redacted in targetUrl inside dossier
  assert.ok(!dossier.targetUrl.includes('pin=9999'));
  assert.ok(dossier.targetUrl.includes('[REDACTED_BY_VERITY]'));
});

// ════════════════════════════════════════════════════════════════════════════════
// 3. Real-Time Bharat Scam Detectors (Digital Arrest, Fake APK, UPI QR)
// ════════════════════════════════════════════════════════════════════════════════

test('Bharat Scam Detectors: detectDigitalArrestAndApkScams catches Digital Arrest extortion', () => {
  const sampleArrest = `
    CENTRAL BUREAU OF INVESTIGATION - CYBER CRIME CELL
    Digital Arrest Notice: An illegal narcotics parcel with your Aadhaar ID was seized by customs.
    You are placed under Virtual Arrest. You must stay on video call (Skype) and transfer money to verify innocence.
  `;
  const result = detectDigitalArrestAndApkScams(sampleArrest, []);
  assert.equal(result.detected, true);
  assert.equal(result.type, 'DIGITAL_ARREST');
  assert.equal(result.signal, 'SIG_DIGITAL_ARREST_EXTORTION');
  assert.match(result.reason, /digital arrest extortion pattern/i);

  // Benign news article about digital arrests should NOT trigger without extortion demands
  const benignNews = 'The Indian Express: What is the Digital Arrest scam? PM Modi warns citizens in Mann Ki Baat.';
  const benignResult = detectDigitalArrestAndApkScams(benignNews, []);
  assert.equal(benignResult.detected, false);
});

test('Bharat Scam Detectors: detectDigitalArrestAndApkScams catches malicious Indian APKs', () => {
  const links1 = ['https://rto-echallan.in/download/RTO_Challan.apk'];
  const res1 = detectDigitalArrestAndApkScams('Click to download your pending challan', links1);
  assert.equal(res1.detected, true);
  assert.equal(res1.type, 'MALICIOUS_APK');
  assert.equal(res1.signal, 'SIG_MALICIOUS_APK_DROPPER');
  assert.equal(res1.filename, 'rto_challan.apk');

  const links2 = ['https://sbi-reward-claim.online/SBI_KYC.apk'];
  const res2 = detectDigitalArrestAndApkScams('Mandatory KYC App', links2);
  assert.equal(res2.detected, true);
  assert.equal(res2.filename, 'sbi_kyc.apk');

  // APK name embedded in body text
  const res3 = detectDigitalArrestAndApkScams('Your Electricity bill is unpaid. Download Electricity_Bill.apk immediately to avoid disconnection.');
  assert.equal(res3.detected, true);
  assert.equal(res3.filename.toLowerCase(), 'electricity_bill.apk');
});

test('Bharat Scam Detectors: detectUpiQrCollectTrap catches fake cashback QR traps', () => {
  // Mock document with receive lure and upi://pay link
  const mockDocWithIntent = {
    body: {
      innerText: 'Congratulations! Scan to receive cashback of ₹2,000 directly into your bank account.'
    },
    querySelectorAll: (sel) => {
      if (sel.includes('upi://pay')) {
        return [{ getAttribute: (attr) => (attr === 'href' ? 'upi://pay?pa=scammer@okaxis&am=2000' : null) }];
      }
      return [];
    }
  };

  const resIntent = detectUpiQrCollectTrap(mockDocWithIntent);
  assert.equal(resIntent.detected, true);
  assert.equal(resIntent.signal, 'SIG_UPI_QR_COLLECT_TRAP');
  assert.match(resIntent.reason, /receive cashback|scan to receive/i);

  // Mock document with QR image element
  const mockDocWithQrImg = {
    body: {
      innerText: 'OLX Buyer Payment: Scan QR code to accept ₹5,000 payment for your used furniture.'
    },
    querySelectorAll: (sel) => {
      if (sel.includes('img') || sel.includes('qr')) {
        return [{ tagName: 'IMG', alt: 'UPI Payment QR' }];
      }
      return [];
    }
  };

  const resQr = detectUpiQrCollectTrap(mockDocWithQrImg);
  assert.equal(resQr.detected, true);
  assert.equal(resQr.signal, 'SIG_UPI_QR_COLLECT_TRAP');

  // Legitimate shopping checkout without receive-money lures
  const mockLegitStore = {
    body: {
      innerText: 'Order Total: ₹850. Pay using UPI or Credit Card.'
    },
    querySelectorAll: () => []
  };
  const resLegit = detectUpiQrCollectTrap(mockLegitStore);
  assert.equal(resLegit.detected, false);
});

// ════════════════════════════════════════════════════════════════════════════════
// 4. Risk Engine Cyber-Fraud Overrides
// ════════════════════════════════════════════════════════════════════════════════

test('Risk Engine: SIG_DIGITAL_ARREST_EXTORTION produces Critical Block (Score >= 85)', () => {
  const result = calculateRisk('https://cbi-virtual-court.in/notice', [], null, {
    digitalArrestExtortion: true,
    digitalArrestPhrase: 'narcotics parcel warrant',
    digitalArrestReason: 'Digital Arrest extortion scam pattern detected'
  });

  assert.equal(result.action, 'block');
  assert.ok(result.score >= 85, `Expected score >= 85, got ${result.score}`);
  assert.ok(result.signals.some(s => s.id === 'SIG_DIGITAL_ARREST_EXTORTION'));
});

test('Risk Engine: SIG_MALICIOUS_APK_DROPPER produces Critical Block (Score >= 90)', () => {
  const result = calculateRisk('https://echallan-portal.online/download', [], null, {
    maliciousApkDropper: true,
    maliciousApkFilename: 'RTO_Challan.apk',
    maliciousApkReason: 'Malicious Android APK dropper detected'
  });

  assert.equal(result.action, 'block');
  assert.ok(result.score >= 90, `Expected score >= 90, got ${result.score}`);
  assert.ok(result.signals.some(s => s.id === 'SIG_MALICIOUS_APK_DROPPER'));
});

test('Risk Engine: SIG_UPI_QR_COLLECT_TRAP produces Critical Block (Score >= 85)', () => {
  const result = calculateRisk('https://olx-cashback-claim.xyz/reward', [], null, {
    upiQrCollectTrap: true,
    upiQrLure: 'claim reward QR trap',
    upiQrReason: 'Deceptive UPI QR code collect trap detected'
  });

  assert.equal(result.action, 'block');
  assert.ok(result.score >= 85, `Expected score >= 85, got ${result.score}`);
  assert.ok(result.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'));
});

// ════════════════════════════════════════════════════════════════════════════════
// 5. Interactive "Spot The Scam" X-Ray Literacy Engine
// ════════════════════════════════════════════════════════════════════════════════

test('X-Ray Educator: parseUrlAnatomy breaks down registered domain vs. deceptive subdomains', () => {
  const anatomy1 = parseUrlAnatomy('https://sbi.online-banking.verification.fraudulent-site.xyz/login');
  assert.equal(anatomy1.registeredDomain, 'fraudulent-site.xyz');
  assert.equal(anatomy1.subdomains, 'sbi.online-banking.verification');
  assert.equal(anatomy1.hostname, 'sbi.online-banking.verification.fraudulent-site.xyz');

  // Multi-level Indian TLD (.co.in, .gov.in)
  const anatomy2 = parseUrlAnatomy('https://incometax.refund-portal.scam.co.in/auth');
  assert.equal(anatomy2.registeredDomain, 'scam.co.in');
  assert.equal(anatomy2.subdomains, 'incometax.refund-portal');
});

test('X-Ray Educator: detectPsychologicalTrigger correctly classifies scam tactics', () => {
  const triggerFear = detectPsychologicalTrigger({
    signals: [{ id: 'SIG_DIGITAL_ARREST_EXTORTION' }]
  });
  assert.equal(triggerFear.type, 'FEAR_AND_AUTHORITY');
  assert.match(triggerFear.badge, /Intimidation Tactic/i);

  const triggerGreed = detectPsychologicalTrigger({
    signals: [{ id: 'SIG_UPI_QR_COLLECT_TRAP' }]
  });
  assert.equal(triggerGreed.type, 'GREED_AND_REWARD');
  assert.match(triggerGreed.badge, /Greed \/ Excitement Tactic/i);

  const triggerUrgency = detectPsychologicalTrigger({
    reasons: ['High pressure electricity disconnection timer active']
  });
  assert.equal(triggerUrgency.type, 'ARTIFICIAL_URGENCY');
});

test('X-Ray Educator: generateXRayTeachingCards generates 3 interactive cards & micro-quiz', () => {
  const analysisResult = {
    signals: [{ id: 'SIG_DIGITAL_ARREST_EXTORTION' }],
    reasons: ['Digital Arrest extortion pattern detected']
  };

  const { cards, totalCards, summaryText } = generateXRayTeachingCards(
    analysisResult,
    'https://cbi.police-cybercell.scam-server.xyz/warrant'
  );

  assert.equal(totalCards, 3);
  assert.equal(cards.length, 3);

  // Card 1: URL Anatomy
  const card1 = cards[0];
  assert.equal(card1.cardType, 'URL_ANATOMY');
  assert.equal(card1.registeredDomain, 'scam-server.xyz');
  assert.equal(card1.subdomains, 'cbi.police-cybercell');
  assert.ok(card1.takeaway.includes('scam-server.xyz'));

  // Card 2: Psychological Tactic
  const card2 = cards[1];
  assert.equal(card2.cardType, 'PSYCHOLOGICAL_TACTIC');
  assert.match(card2.title, /Fear & False Authority/i);
  assert.ok(card2.countermeasure.includes('1930'));

  // Card 3: Interactive Micro-Quiz
  const card3 = cards[2];
  assert.equal(card3.cardType, 'MICRO_QUIZ');
  assert.ok(card3.question.includes('police'));
  assert.equal(card3.options.length, 4);
  assert.equal(typeof card3.correctIndex, 'number');
  assert.ok(card3.options[card3.correctIndex].includes('1930') || card3.options[card3.correctIndex].includes('cybercrime.gov.in'));
  assert.ok(card3.explanation.length > 10);

  assert.ok(summaryText.includes('[Spot The Scam X-Ray]'));
});

// ════════════════════════════════════════════════════════════════════════════════
// 6. Citizen-Friendly Bharat Shield Blocked UI (under 15KB)
// ════════════════════════════════════════════════════════════════════════════════

test('Bharat Shield UI: detectThreatCategory classifies plain-language citizen threats', async () => {
  const { detectThreatCategory, STRINGS, LEGIT } = await import('../ui/blocked.js');

  assert.equal(detectThreatCategory('cbi-police-notice.xyz', 'arrest'), 'SIG_DIGITAL_ARREST_EXTORTION');
  assert.equal(detectThreatCategory('echallan-download.in', 'apk'), 'SIG_MALICIOUS_APK_DROPPER');
  assert.equal(detectThreatCategory('sbi-kyc-verify.top', 'pin'), 'SIG_ILLEGAL_WEB_PIN_COLLECTION');
  assert.equal(detectThreatCategory('olx-reward-cashback.xyz', 'qr'), 'SIG_UPI_QR_COLLECT_TRAP');
  assert.equal(detectThreatCategory('fake-update.com', 'clipboard'), 'SIG_CLICKFIX_CLIPBOARD_ATTACK');
  assert.equal(detectThreatCategory('unknown-phish.com', 'webhook'), 'SIG_PHISHING_KIT_WEBHOOK_EXFIL');

  // Multi-lingual strings validation
  for (const lang of ['en-IN', 'hi-IN', 'ta-IN', 'te-IN']) {
    assert.ok(STRINGS[lang], `Missing strings for lang ${lang}`);
    assert.equal(STRINGS[lang].length, 7);
  }

  // Known Indian Legit Pairs
  assert.ok(LEGIT.sbi);
  assert.equal(LEGIT.sbi[1], 'onlinesbi.sbi');
  assert.ok(LEGIT.incometax);
  assert.equal(LEGIT.incometax[1], 'incometax.gov.in');
});

test('Bharat Shield UI: Ultra-Lightweight Bundle Size is strictly under 15KB total', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');

  const htmlSize = fs.statSync(path.resolve('ui/blocked.html')).size;
  const cssSize = fs.statSync(path.resolve('ui/blocked.css')).size;
  const jsSize = fs.statSync(path.resolve('ui/blocked.js')).size;
  const totalBytes = htmlSize + cssSize + jsSize;

  assert.ok(
    totalBytes < 15360,
    `Total UI bundle size must be under 15KB (15360 bytes), got ${totalBytes} bytes (${(totalBytes / 1024).toFixed(2)} KB)`
  );
});

