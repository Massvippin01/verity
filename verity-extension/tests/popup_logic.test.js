import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isInternalUrl,
  extractDomain,
  detectEffectiveLang,
  getRotatingGenericRule,
  resolvePlainReasons,
  formatTabViewModel,
  formatScanResult
} from '../popup/popup-logic.js';
import { STATUS, UI, GOLDEN_RULES, REASON_PLAIN } from '../shared/citizen-messages.js';

test('Popup Logic: isInternalUrl correctly detects browser internal and extension URLs', () => {
  assert.equal(isInternalUrl('chrome://extensions'), true);
  assert.equal(isInternalUrl('about:blank'), true);
  assert.equal(isInternalUrl('chrome-extension://abc/popup/popup.html'), true);
  assert.equal(isInternalUrl('edge://settings'), true);
  assert.equal(isInternalUrl('view-source:https://example.com'), true);
  assert.equal(isInternalUrl(''), true);
  assert.equal(isInternalUrl(null), true);
  assert.equal(isInternalUrl('https://onlinesbi.sbi'), false);
  assert.equal(isInternalUrl('http://insecure-site.org/login'), false);
});

test('Popup Logic: extractDomain handles protocols, hostnames, and malformed strings', () => {
  assert.equal(extractDomain('https://sub.bank.in/portal'), 'sub.bank.in');
  assert.equal(extractDomain('http://192.168.1.1:8080/'), '192.168.1.1');
  assert.equal(extractDomain('chrome://newtab'), 'newtab');
  assert.equal(extractDomain('not a url'), 'not a url');
});

test('Popup Logic: detectEffectiveLang honors valid storedLang or falls back to navigator/English', () => {
  assert.equal(detectEffectiveLang('ta', 'en-US'), 'ta');
  assert.equal(detectEffectiveLang('hi', 'te-IN'), 'hi');
  assert.equal(detectEffectiveLang('te', 'en'), 'te');
  assert.equal(detectEffectiveLang(null, 'ta-IN'), 'ta');
  assert.equal(detectEffectiveLang(null, 'hi_IN'), 'hi');
  assert.equal(detectEffectiveLang(null, 'te-AP'), 'te');
  assert.equal(detectEffectiveLang(null, 'fr-FR'), 'en');
  assert.equal(detectEffectiveLang('invalid_lang', 'en-US'), 'en');
});

test('Popup Logic: getRotatingGenericRule produces deterministic daily rule keys', () => {
  const d1 = new Date('2026-10-22T00:00:00Z');
  const d2 = new Date('2026-10-23T00:00:00Z');
  const rule1 = getRotatingGenericRule(d1);
  const rule2 = getRotatingGenericRule(d2);

  const validKeys = ['upi', 'digital_arrest', 'apk', 'otp_password', 'generic'];
  assert.ok(validKeys.includes(rule1));
  assert.ok(validKeys.includes(rule2));
});

test('Popup Logic: resolvePlainReasons never outputs raw technical signal IDs', () => {
  const technicalSignals = [
    { id: 'SIG_DIGITAL_ARREST_EXTORTION' },
    { id: 'SIG_MALICIOUS_APK_DROPPER' },
    { id: 'RULE_BRAND_NAME_WRONG_DOMAIN' }
  ];

  for (const lang of ['en', 'ta', 'hi', 'te']) {
    const reasons = resolvePlainReasons(technicalSignals, lang, 3);
    assert.equal(reasons.length, 3);
    for (const text of reasons) {
      assert.ok(typeof text === 'string' && text.length > 5);
      assert.equal(text.includes('SIG_'), false, `Reason contains raw signal ID: ${text}`);
      assert.equal(text.includes('RULE_'), false, `Reason contains raw rule ID: ${text}`);
    }
  }
});

test('Popup Logic: formatTabViewModel for Safe website (score 0)', () => {
  const tab = { id: 1, url: 'https://onlinesbi.sbi' };
  const verdict = { url: 'https://onlinesbi.sbi', score: 0, severity: 'SAFE', action: 'ALLOW', signals: [] };

  const vmEn = formatTabViewModel(tab, verdict, 'en');
  assert.equal(vmEn.status, 'safe');
  assert.equal(vmEn.statusText, 'SAFE WEBSITE');
  assert.equal(vmEn.domain, 'onlinesbi.sbi');
  assert.equal(vmEn.score, 0);
  assert.equal(vmEn.plainReasons.length, 0);
  assert.ok(vmEn.goldenRuleText.length > 0);

  const vmTa = formatTabViewModel(tab, verdict, 'ta');
  assert.equal(vmTa.statusText, 'பாதுகாப்பான தளம்');

  const vmHi = formatTabViewModel(tab, verdict, 'hi');
  assert.equal(vmHi.statusText, 'सुरक्षित वेबसाइट');

  const vmTe = formatTabViewModel(tab, verdict, 'te');
  assert.equal(vmTe.statusText, 'సురక్షితమైన వెబ్‌సైట్');
});

test('Popup Logic: formatTabViewModel for Caution website (score 45)', () => {
  const tab = { id: 2, url: 'http://unverified-tracker.biz/click' };
  const verdict = {
    url: 'http://unverified-tracker.biz/click',
    score: 45,
    severity: 'MEDIUM',
    action: 'WARN',
    signals: [
      { id: 'RULE_MISSING_HTTPS' },
      { id: 'RULE_IP_BASED_URL' }
    ]
  };

  const vm = formatTabViewModel(tab, verdict, 'en');
  assert.equal(vm.status, 'caution');
  assert.equal(vm.statusText, 'BE CAREFUL');
  assert.equal(vm.score, 45);
  assert.ok(vm.plainReasons.length >= 1 && vm.plainReasons.length <= 2);
  assert.equal(vm.plainReasons[0].includes('RULE_'), false);
});

test('Popup Logic: formatTabViewModel for Danger website (score 85, Digital Arrest)', () => {
  const tab = { id: 3, url: 'https://cbi-investigation-notice.top/warrant' };
  const verdict = {
    url: 'https://cbi-investigation-notice.top/warrant',
    score: 85,
    severity: 'CRITICAL',
    action: 'BLOCK',
    signals: [
      { id: 'SIG_DIGITAL_ARREST_EXTORTION' },
      { id: 'RULE_BRAND_NAME_WRONG_DOMAIN' }
    ]
  };

  const vm = formatTabViewModel(tab, verdict, 'en');
  assert.equal(vm.status, 'danger');
  assert.equal(vm.statusText, 'DANGER: SCAM DETECTED');
  assert.equal(vm.score, 85);
  assert.equal(vm.goldenRuleKey, 'digital_arrest');
  assert.ok(vm.plainReasons.length >= 1 && vm.plainReasons.length <= 3);
  assert.equal(vm.plainReasons[0].includes('SIG_'), false);
  assert.ok(vm.goldenRuleText.includes('video calls') || vm.goldenRuleText.includes('arrest'));
});

test('Popup Logic: formatTabViewModel for Internal/Unscannable browser page', () => {
  const tab = { id: 4, url: 'chrome://settings' };
  const verdict = null;

  for (const lang of ['en', 'ta', 'hi', 'te']) {
    const vm = formatTabViewModel(tab, verdict, lang);
    assert.equal(vm.isInternal, true);
    assert.equal(vm.status, 'neutral');
    assert.ok(vm.statusText.length > 0);
    assert.equal(vm.score, 0);
    assert.equal(vm.plainReasons.length, 0);
  }
});

test('Popup Logic: formatScanResult formats pasted quick scanner outputs', () => {
  const scamScan = {
    verdict: 'danger',
    score: 90,
    signals: [{ id: 'SIG_MALICIOUS_APK_DROPPER', plainKey: 'SIG_MALICIOUS_APK_DROPPER' }],
    extracted: { urls: ['https://rto.in/challan.apk'], upi: null, apkNames: ['challan.apk'] },
    goldenRuleKey: 'apk'
  };

  const vm = formatScanResult(scamScan, 'en');
  assert.equal(vm.status, 'danger');
  assert.equal(vm.score, 90);
  assert.equal(vm.goldenRuleKey, 'apk');
  assert.ok(vm.goldenRuleText.includes('.apk'));
  assert.equal(vm.plainReasons.length, 1);
  assert.equal(vm.plainReasons[0].includes('SIG_'), false);
});

test('Popup Logic: formatTabViewModel seamlessly handles calculateRisk return shape (lowercase action/severity, riskScore)', () => {
  const tab = { id: 10, url: 'https://login.ipkopl.com/auth/login.php' };
  // Exactly matching what calculateRisk returns:
  const riskEngineVerdict = {
    url: 'https://login.ipkopl.com/auth/login.php',
    riskScore: 92,
    score: 92,
    severity: 'danger',
    state: 'danger',
    action: 'block',
    signals: [
      { id: 'SIG_AITM_REVERSE_PROXY_PHISH', score: 92 }
    ],
    reasons: ['AiTM reverse proxy detected']
  };

  const vm = formatTabViewModel(tab, riskEngineVerdict, 'en');
  assert.equal(vm.status, 'danger', 'Must resolve to danger status');
  assert.equal(vm.score, 92, 'Score must be 92');
  assert.equal(vm.statusText, 'DANGER: SCAM DETECTED');
  assert.equal(vm.domain, 'login.ipkopl.com');

  // Also verify caution state with lowercase action
  const warnVerdict = {
    url: 'https://suspicious-shortener.click',
    riskScore: 48,
    action: 'warn',
    severity: 'caution',
    signals: [{ id: 'RULE_SUSPICIOUS_URL_PATTERN', score: 48 }]
  };
  const vmWarn = formatTabViewModel(tab, warnVerdict, 'en');
  assert.equal(vmWarn.status, 'caution');
  assert.equal(vmWarn.score, 48);
  assert.equal(vmWarn.statusText, 'BE CAREFUL');
});

