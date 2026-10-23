import test from 'node:test';
import assert from 'node:assert/strict';
import { scanText, parseUpiString, extractUrls } from '../shared/text-scanner.js';
import {
  LANGS,
  STATUS,
  UI,
  GOLDEN_RULES,
  REASON_PLAIN,
  goldenRuleForSignal,
  getText,
  detectDefaultLang
} from '../shared/citizen-messages.js';
import brands from '../brands.json' with { type: 'json' };

test('Text Scanner: 1. Fake SBI KYC URL returns danger verdict', () => {
  const input = 'Urgent update: Click https://sbi-kyc-verify.top/x to verify your account';
  const result = scanText(input, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 70, `Expected score >= 70, got ${result.score}`);
  assert.ok(result.extracted.urls.includes('https://sbi-kyc-verify.top/x'));
  assert.equal(result.goldenRuleKey, 'otp_password');
});

test('Text Scanner: 2. Legitimate onlinesbi.sbi returns safe verdict', () => {
  const result = scanText('https://onlinesbi.sbi', { brandsList: brands });

  assert.equal(result.verdict, 'safe');
  assert.equal(result.score, 0);
  assert.ok(result.extracted.urls.includes('https://onlinesbi.sbi'));
  assert.equal(result.signals.length, 0);
});

test('Text Scanner: 3. Legitimate irctc.co.in returns safe verdict', () => {
  const result = scanText('Book tickets at https://www.irctc.co.in/nget/', { brandsList: brands });

  assert.equal(result.verdict, 'safe');
  assert.equal(result.score, 0);
  assert.ok(result.extracted.urls.length >= 1);
});

test('Text Scanner: 4. Legitimate digilocker.gov.in returns safe verdict', () => {
  const result = scanText('Access your verified docs at https://digilocker.gov.in', { brandsList: brands });

  assert.equal(result.verdict, 'safe');
  assert.equal(result.score, 0);
});

test('Text Scanner: 5. CBI Digital Arrest WhatsApp text returns danger verdict', () => {
  const text = 'Urgent Notice: CBI cyber crime cell notice. You are placed under digital arrest for illegal narcotics parcel. Connect to video call immediately or arrest warrant will be executed.';
  const result = scanText(text, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 80, `Expected score >= 80, got ${result.score}`);
  assert.equal(result.goldenRuleKey, 'digital_arrest');
  assert.ok(result.signals.some(s => s.id === 'SIG_DIGITAL_ARREST_EXTORTION'));
});

test('Text Scanner: 6. Malicious RTO_Challan.apk link returns danger verdict and extracts APK name', () => {
  const text = 'Download your pending traffic fine slip: https://echallan-parivahan.in/download/RTO_Challan.apk';
  const result = scanText(text, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 80, `Expected score >= 80, got ${result.score}`);
  assert.equal(result.goldenRuleKey, 'apk');
  assert.ok(result.signals.some(s => s.id === 'SIG_MALICIOUS_APK_DROPPER'));
  assert.ok(result.extracted.apkNames.some(name => name.toLowerCase() === 'rto_challan.apk'));
});

test('Text Scanner: 7. Deceptive upi://pay refund lure returns danger verdict', () => {
  const input = 'upi://pay?pa=x@ybl&am=15000&tn=OLX refund';
  const result = scanText(input, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 70, `Expected score >= 70, got ${result.score}`);
  assert.equal(result.goldenRuleKey, 'upi');
  assert.ok(result.extracted.upi !== null);
  assert.equal(result.extracted.upi.isCollect, true);
  assert.equal(result.extracted.upi.am, '15000');
  assert.ok(result.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'));
});

test('Text Scanner: 8. Benign conversational message returns safe verdict', () => {
  const text = 'Hi Ramesh, let us meet for lunch tomorrow at 1:30 PM near the metro station.';
  const result = scanText(text, { brandsList: brands });

  assert.equal(result.verdict, 'safe');
  assert.equal(result.score, 0);
  assert.equal(result.signals.length, 0);
  assert.equal(result.extracted.urls.length, 0);
  assert.equal(result.extracted.upi, null);
});

test('Text Scanner: 9. Empty string returns safe default without throwing', () => {
  const result = scanText('');

  assert.equal(result.verdict, 'safe');
  assert.equal(result.score, 0);
  assert.deepEqual(result.signals, []);
  assert.deepEqual(result.extracted.urls, []);
  assert.equal(result.extracted.upi, null);
  assert.deepEqual(result.extracted.apkNames, []);
});

test('Text Scanner: 10. 10,000-character random garbage string never throws and returns safe', () => {
  const garbage = 'a7#$@! 9x \n\t '.repeat(1000);
  assert.doesNotThrow(() => {
    const result = scanText(garbage, { brandsList: brands });
    assert.equal(result.verdict, 'safe');
    assert.equal(result.score, 0);
  });
});

test('Text Scanner: 11. Mixed text containing legitimate text and one phishing URL catches the threat', () => {
  const text = 'Check favorite cooking recipes at https://healthy-food.org and also verify your bank immediately at sbi-kyc-verify.top/login to avoid suspension.';
  const result = scanText(text, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 70, `Expected score >= 70, got ${result.score}`);
  assert.ok(result.extracted.urls.length >= 2);
});

test('Text Scanner: 12. Hindi scam message returns danger verdict', () => {
  const text = 'प्रिय ग्राहक, आपका एसबीआई बैंक खाता बंद कर दिया गया है। तुरंत अपना केवाईसी अपडेट करें: sbi-kyc-verify.top/kyc';
  const result = scanText(text, { brandsList: brands });

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 70);
  assert.equal(result.goldenRuleKey, 'otp_password');
  assert.ok(result.signals.length > 0);
});

test('Text Scanner: 13. Completeness check: citizen-messages keys exist in all 4 languages with non-empty values', () => {
  const requiredLangs = ['en', 'ta', 'hi', 'te'];

  // Check LANGS metadata
  assert.equal(LANGS.length, 4);
  for (const lang of LANGS) {
    assert.ok(requiredLangs.includes(lang.code));
    assert.ok(lang.label && lang.short);
  }

  // Check STATUS strings
  for (const l of requiredLangs) {
    assert.ok(STATUS[l], `Missing STATUS for ${l}`);
    for (const statusKey of ['safe', 'caution', 'danger']) {
      const val = STATUS[l][statusKey];
      assert.ok(typeof val === 'string' && val.trim().length > 0, `Missing STATUS.${l}.${statusKey}`);
    }
  }

  // Check UI strings
  const expectedUiKeys = [
    'checkButton',
    'pastePlaceholder',
    'whyTitle',
    'backToSafety',
    'goldenRuleTitle',
    'currentSite',
    'quickChecker',
    'noThreatFound',
    'advancedDetails',
    'nothingToCheck',
    'privacyLine'
  ];
  for (const l of requiredLangs) {
    assert.ok(UI[l], `Missing UI for ${l}`);
    for (const uiKey of expectedUiKeys) {
      const val = UI[l][uiKey];
      assert.ok(typeof val === 'string' && val.trim().length > 0, `Missing UI.${l}.${uiKey}`);
    }
  }

  // Check GOLDEN_RULES
  const expectedRules = ['upi', 'digital_arrest', 'apk', 'otp_password', 'generic'];
  for (const ruleKey of expectedRules) {
    assert.ok(GOLDEN_RULES[ruleKey], `Missing GOLDEN_RULES.${ruleKey}`);
    for (const l of requiredLangs) {
      const val = GOLDEN_RULES[ruleKey][l];
      assert.ok(typeof val === 'string' && val.trim().length > 0, `Missing GOLDEN_RULES.${ruleKey}.${l}`);
    }
  }

  // Check REASON_PLAIN for all 10 required signals
  const requiredSignals = [
    'SIG_DIGITAL_ARREST_EXTORTION',
    'SIG_MALICIOUS_APK_DROPPER',
    'SIG_ILLEGAL_WEB_PIN_COLLECTION',
    'SIG_UPI_QR_COLLECT_TRAP',
    'SIG_TYPOSQUATTING',
    'SIG_HOMOGRAPH_ATTACK',
    'RULE_BRAND_NAME_WRONG_DOMAIN',
    'RULE_IP_BASED_URL',
    'RULE_MISSING_HTTPS',
    'SIG_AITM_REVERSE_PROXY_PHISH'
  ];
  for (const sigId of requiredSignals) {
    assert.ok(REASON_PLAIN[sigId], `Missing REASON_PLAIN.${sigId}`);
    for (const l of requiredLangs) {
      const val = REASON_PLAIN[sigId][l];
      assert.ok(typeof val === 'string' && val.trim().length > 0, `Missing REASON_PLAIN.${sigId}.${l}`);
    }
  }

  // Check helpers
  assert.equal(getText('ta', 'STATUS.safe'), 'பாதுகாப்பான தளம்');
  assert.equal(getText('es', 'STATUS.safe'), 'SAFE WEBSITE'); // Fallback
  assert.equal(detectDefaultLang('ta-IN'), 'ta');
  assert.equal(detectDefaultLang('hi_IN'), 'hi');
  assert.equal(detectDefaultLang('te'), 'te');
  assert.equal(detectDefaultLang('en-US'), 'en');
  assert.equal(detectDefaultLang('de-DE'), 'en');
  assert.equal(goldenRuleForSignal('SIG_DIGITAL_ARREST_EXTORTION'), 'digital_arrest');
  assert.equal(goldenRuleForSignal('SIG_MALICIOUS_APK_DROPPER'), 'apk');
  assert.equal(goldenRuleForSignal('SIG_UPI_QR_COLLECT_TRAP'), 'upi');
  assert.equal(goldenRuleForSignal('SIG_AITM_REVERSE_PROXY_PHISH'), 'otp_password');
});

test('Text Scanner: 14. parseUpiString pure tests for benign payment vs collect trap', () => {
  // Benign merchant checkout (no cashback / refund / receive lure)
  const benignUpi = parseUpiString('upi://pay?pa=store@icici&pn=Coffee%20Shop&am=250&tn=Espresso');
  assert.ok(benignUpi !== null);
  assert.equal(benignUpi.pa, 'store@icici');
  assert.equal(benignUpi.am, '250');
  assert.equal(benignUpi.isCollect, false);

  // Malicious cashback lure
  const scamUpi = parseUpiString('upi://pay?pa=hacker@oksbi&am=5000&tn=Cashback%20Reward');
  assert.ok(scamUpi !== null);
  assert.equal(scamUpi.isCollect, true);

  // Non-UPI string returns null
  assert.equal(parseUpiString('https://google.com'), null);
});

test('Text Scanner: 15. Injected PSL option is accepted by scanText', () => {
  const customPsl = {
    getDomain: (host) => host.split('.').slice(-2).join('.'),
    getPublicSuffix: () => 'com'
  };
  const result = scanText('https://example.com/test', { brandsList: brands, psl: customPsl });
  assert.equal(result.verdict, 'safe');
});
