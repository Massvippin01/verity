/**
 * tests/bitdefender_and_mobile_sensors.test.js
 *
 * Verification suite for:
 * 1. Bitdefender-grade Compromised CMS Deep-Path & PHP Mailer Phishing Detection
 * 2. SERP Sponsored Search Ad Impersonation & Redirect Unwrapping
 * 3. In-Browser Android .APK Permission & Bytecode Decompiler
 * 4. Live Scam Call Speakerphone AI Guardian
 * 5. Multilingual Citizen Translations & Golden Rules
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { detectCompromisedHostPhishing } from '../background/compromised-site-detector.js';
import { calculateRisk } from '../background/risk-engine.js';
import { evaluateSearchResultLink, unwrapSearchDestinationUrl } from '../content/search-shield.js';
import { decompileAndAuditApkBuffer } from '../shared/apk-bytecode-analyzer.js';
import { evaluateLiveCallTranscriptChunk } from '../shared/live-call-guardian.js';
import { REASON_PLAIN, goldenRuleForSignal, getText } from '../shared/citizen-messages.js';

test('1. Compromised CMS Phish: Detects bank login inside hacked WordPress /uploads/ deep path', () => {
  const url = 'https://bakery-shop.com/wp-content/uploads/2026/sbi-netbanking/post.php';
  const domSignals = {
    hasPasswordInput: true,
    hasForm: true,
    formAction: 'post.php'
  };

  const result = detectCompromisedHostPhishing(url, domSignals);
  assert.equal(result.detected, true);
  assert.equal(result.signal, 'SIG_COMPROMISED_CMS_HOST_PHISH');
  assert.equal(result.score, 88);
  assert.ok(result.hasCmsInjectionPath);
  assert.ok(result.hasPhpOrGateEndpoint);
});

test('2. Compromised CMS Phish: Detects deep nested cPanel gate endpoint with OTP inputs', () => {
  const url = 'https://local-electrician.in/assets/temp/secure/auth/gate.php';
  const domSignals = {
    hasOtpInput: true,
    textMentionsBrand: 'hdfc'
  };

  const result = detectCompromisedHostPhishing(url, domSignals);
  assert.equal(result.detected, true);
  assert.equal(result.score, 88);
  assert.ok(result.pathDepth >= 4);
});

test('3. Compromised CMS Phish (Risk Engine): Enforces Hard Override danger block on aged domain', () => {
  const url = 'https://bakery-shop.com/wp-content/uploads/2026/sbi-netbanking/post.php';
  const domSignals = {
    hasPasswordInput: true,
    hasForm: true,
    formAction: 'post.php'
  };

  const verdict = calculateRisk(url, [], null, domSignals);

  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 88);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_COMPROMISED_CMS_HOST_PHISH'));
});

test('4. Compromised CMS Zero False Positive: Normal WordPress blog article is marked safe', () => {
  const url = 'https://bakery-shop.com/2026/best-chocolate-cakes/';
  const domSignals = {
    hasPasswordInput: false,
    hasForm: false
  };

  const result = detectCompromisedHostPhishing(url, domSignals);
  assert.equal(result.detected, false);
  assert.equal(result.score, 0);

  const verdict = calculateRisk(url, [], null, domSignals);
  assert.notEqual(verdict.severity, 'danger');
  assert.ok(!verdict.signals.some(s => s.id === 'SIG_COMPROMISED_CMS_HOST_PHISH'));
});

test('5. Compromised CMS Zero False Positive: Official WordPress login page is not falsely flagged', () => {
  const url = 'https://wordpress.org/wp-login.php';
  const domSignals = {
    hasPasswordInput: true,
    hasForm: true
  };

  const result = detectCompromisedHostPhishing(url, domSignals);
  assert.equal(result.detected, false);
});

test('6. SERP Shield: Google sponsored ad impersonating SBI customer care helpline', () => {
  const adHref = 'https://sbi-helpdesk-india.top/helpline';
  const adTitle = 'SBI Official Customer Care - 24x7 Helpline Support';

  const res = evaluateSearchResultLink(adHref, adTitle, true);
  assert.equal(res.status, 'danger');
  assert.ok(res.score >= 90);
  assert.equal(res.signal, 'SIG_SERP_SPONSORED_IMPERSONATION');
  assert.equal(res.matchedBrand, 'State Bank of India');
});

test('7. SERP Shield: Malvertising ad impersonating software download (AnyDesk Remote)', () => {
  const adHref = 'https://anydesk-fast-download.xyz/setup.exe';
  const adTitle = 'Download AnyDesk - Free Remote Desktop Software';

  const res = evaluateSearchResultLink(adHref, adTitle, true);
  assert.equal(res.status, 'danger');
  assert.ok(res.score >= 90);
  assert.equal(res.signal, 'SIG_SERP_SPONSORED_IMPERSONATION');
  assert.equal(res.matchedBrand, 'AnyDesk');
});

test('8. SERP Shield: Unwraps Google /aclk redirect to inspect hidden destination', () => {
  const googleAclk = 'https://www.google.com/aclk?sa=l&ai=DChcSEwj&adurl=https%3A%2F%2Fsbi-helpdesk-india.top%2Flogin';
  const unwrapped = unwrapSearchDestinationUrl(googleAclk);
  assert.equal(unwrapped, 'https://sbi-helpdesk-india.top/login');

  const res = evaluateSearchResultLink(googleAclk, 'SBI Online Banking Portal', true);
  assert.equal(res.status, 'danger');
  assert.equal(res.matchedBrand, 'State Bank of India');
});

test('9. SERP Shield Zero False Positive: Official SBI and AnyDesk links are marked safe', () => {
  const sbiRes = evaluateSearchResultLink('https://www.onlinesbi.sbi/portal', 'State Bank of India - Personal Banking', false);
  assert.equal(sbiRes.status, 'safe');
  assert.equal(sbiRes.score, 0);

  const anydeskRes = evaluateSearchResultLink('https://anydesk.com/en/downloads', 'Download AnyDesk for Windows', true);
  assert.equal(anydeskRes.status, 'safe');
  assert.equal(anydeskRes.score, 0);
});

test('10. APK Bytecode Decompiler: Trojan buffer with SMS theft, Accessibility RAT, and Telegram C2', () => {
  const header = [0x50, 0x4b, 0x03, 0x04]; // PK\x03\x04
  const payload = [
    'AndroidManifest.xml',
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.BIND_ACCESSIBILITY_SERVICE',
    'https://api.telegram.org/bot728391:AAFakeBotToken/sendMessage'
  ].join(' ');
  const payloadBytes = new TextEncoder().encode(payload);
  const buffer = new Uint8Array(header.length + payloadBytes.length);
  buffer.set(header, 0);
  buffer.set(payloadBytes, header.length);

  const res = decompileAndAuditApkBuffer(buffer, 'RTO_Challan.apk');
  assert.equal(res.isMaliciousApk, true);
  assert.ok(res.score >= 95);
  assert.equal(res.signal, 'SIG_APK_TROJAN_BYTECODE_DETECTED');
  assert.ok(res.detectedPermissions.includes('READ_SMS'));
  assert.ok(res.detectedPermissions.includes('RECEIVE_SMS'));
  assert.ok(res.detectedPermissions.includes('BIND_ACCESSIBILITY_SERVICE'));
  assert.ok(res.embeddedC2Endpoints.some(c => c.includes('api.telegram.org/bot')));
});

test('11. APK Bytecode Decompiler: Detects UTF-16LE binary strings in compiled AXML pools', () => {
  const header = [0x50, 0x4b, 0x03, 0x04];
  const targetStr = 'android.permission.SYSTEM_ALERT_WINDOW';
  const utf16Bytes = [];
  for (let i = 0; i < targetStr.length; i++) {
    const code = targetStr.charCodeAt(i);
    utf16Bytes.push(code & 0xff);
    utf16Bytes.push((code >> 8) & 0xff);
  }

  const buffer = new Uint8Array(header.length + utf16Bytes.length);
  buffer.set(header, 0);
  buffer.set(utf16Bytes, header.length);

  const res = decompileAndAuditApkBuffer(buffer, 'Banking_Overlay.apk');
  assert.ok(res.detectedPermissions.includes('SYSTEM_ALERT_WINDOW'));
});

test('12. APK Bytecode Decompiler: Detects hidden Ngrok tunnel C2 gateway in DEX buffer', () => {
  const header = [0x50, 0x4b, 0x03, 0x04];
  const payload = 'classes.dex http://stealer-c2.ngrok-free.app/gate.php android.permission.READ_CALL_LOG';
  const textBytes = new TextEncoder().encode(payload);
  const buffer = new Uint8Array(header.length + textBytes.length);
  buffer.set(header, 0);
  buffer.set(textBytes, header.length);

  const res = decompileAndAuditApkBuffer(buffer, 'PM_Kisan_Yojana.apk');
  assert.equal(res.isMaliciousApk, true);
  assert.ok(res.embeddedC2Endpoints.some(c => c.includes('ngrok-free.app')));
  assert.ok(res.detectedPermissions.includes('READ_CALL_LOG'));
});

test('13. APK Bytecode Decompiler Zero False Positive: Benign calculator APK has low risk', () => {
  const header = [0x50, 0x4b, 0x03, 0x04];
  const payload = 'AndroidManifest.xml android.permission.VIBRATE android.permission.INTERNET classes.dex';
  const textBytes = new TextEncoder().encode(payload);
  const buffer = new Uint8Array(header.length + textBytes.length);
  buffer.set(header, 0);
  buffer.set(textBytes, header.length);

  const res = decompileAndAuditApkBuffer(buffer, 'Scientific_Calculator.apk');
  assert.equal(res.isMaliciousApk, false);
  assert.ok(res.score < 50);
  assert.equal(res.embeddedC2Endpoints.length, 0);
});

test('14. Live Call Guardian: Detects CBI Digital Arrest extortion call stream', () => {
  const transcript = 'Hello I am Inspector Sharma from CBI Mumbai, your Aadhaar was found in a narcotics parcel, stay on video call';
  const res = evaluateLiveCallTranscriptChunk('stay on video call', transcript);

  assert.equal(res.severity, 'danger');
  assert.equal(res.score, 95);
  assert.equal(res.signal, 'SIG_LIVE_CALL_DIGITAL_ARREST');
  assert.equal(res.threatType, 'digital_arrest');
});

test('15. Live Call Guardian: Detects AnyDesk / Remote screen-sharing trap call', () => {
  const transcript = 'Sir please open Play Store and install AnyDesk and tell me the 9 digit code';
  const res = evaluateLiveCallTranscriptChunk('install AnyDesk and tell me the 9 digit code', transcript);

  assert.equal(res.severity, 'danger');
  assert.equal(res.score, 95);
  assert.equal(res.signal, 'SIG_LIVE_CALL_REMOTE_ACCESS_TRAP');
  assert.equal(res.threatType, 'remote_access_trap');
});

test('16. Live Call Guardian: Detects OTP / Bank PIN harvesting call', () => {
  const transcript = 'Sir please read the 6 digit otp code and enter amount in upi';
  const res = evaluateLiveCallTranscriptChunk('enter amount in upi', transcript);

  assert.equal(res.severity, 'danger');
  assert.equal(res.score, 90);
  assert.equal(res.signal, 'SIG_LIVE_CALL_OTP_HARVEST');
  assert.equal(res.threatType, 'otp_harvest');
});

test('17. Live Call Guardian Zero False Positive: Normal family phone call is safe', () => {
  const transcript = 'Hi Mom, I will reach home by 8 PM, please keep dinner ready';
  const res = evaluateLiveCallTranscriptChunk('please keep dinner ready', transcript);

  assert.equal(res.severity, 'safe');
  assert.equal(res.score, 0);
  assert.equal(res.matchedSignals.length, 0);
});

test('18. Multilingual Coverage & Golden Rules: All 6 new signals have 4-language translations and golden rules', () => {
  const signals = [
    'SIG_COMPROMISED_CMS_HOST_PHISH',
    'SIG_SERP_SPONSORED_IMPERSONATION',
    'SIG_APK_TROJAN_BYTECODE_DETECTED',
    'SIG_LIVE_CALL_REMOTE_ACCESS_TRAP',
    'SIG_LIVE_CALL_DIGITAL_ARREST',
    'SIG_LIVE_CALL_OTP_HARVEST'
  ];

  const langs = ['en', 'ta', 'hi', 'te'];

  for (const sig of signals) {
    assert.ok(REASON_PLAIN[sig], `Signal ${sig} must exist in REASON_PLAIN`);
    for (const l of langs) {
      const text = REASON_PLAIN[sig][l];
      assert.ok(typeof text === 'string' && text.length > 5, `Signal ${sig} must have ${l} translation`);
      const viaGetText = getText(l, `REASON_PLAIN.${sig}`);
      assert.ok(viaGetText && viaGetText.length > 5, `getText must retrieve ${sig} for ${l}`);
    }

    const ruleKey = goldenRuleForSignal(sig);
    assert.ok(['upi', 'digital_arrest', 'apk', 'otp_password', 'generic'].includes(ruleKey), `Golden rule for ${sig} must be valid`);
  }

  assert.equal(goldenRuleForSignal('SIG_LIVE_CALL_DIGITAL_ARREST'), 'digital_arrest');
  assert.equal(goldenRuleForSignal('SIG_LIVE_CALL_REMOTE_ACCESS_TRAP'), 'apk');
  assert.equal(goldenRuleForSignal('SIG_APK_TROJAN_BYTECODE_DETECTED'), 'apk');
  assert.equal(goldenRuleForSignal('SIG_COMPROMISED_CMS_HOST_PHISH'), 'otp_password');
});
