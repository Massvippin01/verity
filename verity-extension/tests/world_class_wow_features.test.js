/**
 * tests/world_class_wow_features.test.js — Verification Suite for 4 "World-Class" Security Features
 *
 * Verifies:
 * 1. Deep NPCI UPI Protocol Forensic Unmasker (shared/upi-forensics.js & shared/text-scanner.js)
 * 2. Cross-Origin Brand Asset Leeching & Visual Favicon Trap (content/content-script.js)
 * 3. Live Luhn Card & OTP Keystroke Guard with Honey-Token Poisoning (content/content-script.js)
 * 4. Anti-Doxxing WebRTC & Surveillance Trap for Digital Arrest Scams (content/bharat-scam-detectors.js)
 * 5. Central Risk Engine Hard Overrides & Multilingual Citizen Advisories (en, ta, hi, te)
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  analyzeUpiIntentForensics,
  SUSPICIOUS_VPA_LOCAL_PATTERNS,
  CONSUMER_PSP_HANDLES
} from '../shared/upi-forensics.js';

import { scanText } from '../shared/text-scanner.js';
import { calculateRisk } from '../background/risk-engine.js';
import { detectDigitalArrestSurveillanceTrap } from '../content/bharat-scam-detectors.js';
import { getText, goldenRuleForSignal } from '../shared/citizen-messages.js';
import { t } from '../shared/messages.js';

// Import content-script exports
import '../content/content-script.js';
const {
  detectCrossOriginBrandAssetTheft,
  isLuhnValidCard,
  poisonInputWithHoneyToken,
  detectSensitiveInputTrap
} = globalThis;

// ════════════════════════════════════════════════════════════════════════════════
// 1. NPCI UPI PROTOCOL FORENSIC UNMASKER TESTS
// ════════════════════════════════════════════════════════════════════════════════

test('NPCI Forensics 1: Flags unsigned P2P collect trap with hardcoded amount and deceptive refund context', () => {
  const uri = 'upi://pay?pa=refund.care@oksbi&pn=SBI+Refund+Portal&am=4999&tn=Instant+Refund+Credit';
  const forensics = analyzeUpiIntentForensics(uri, 'Congratulations! Your refund is ready to credit.');

  assert.equal(forensics.detected, true);
  assert.equal(forensics.signal, 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC');
  assert.equal(forensics.score, 90);
  assert.equal(forensics.verdict, 'danger');
  assert.equal(forensics.isUnsignedP2P, true);
  assert.equal(forensics.hasHardcodedDebitAmount, true);
  assert.equal(forensics.hasDeceptiveNoteOrContext, true);
  assert.equal(forensics.hasSuspiciousVpaHandle, true);
  assert.equal(forensics.payeeVpa, 'refund.care@oksbi');
  assert.equal(forensics.debitAmount, 4999);
  assert.equal(forensics.isSignedMerchant, false);

  assert.ok(forensics.forensicBreakdown);
  assert.equal(forensics.forensicBreakdown.payeeVpa, 'refund.care@oksbi');
  assert.equal(forensics.forensicBreakdown.isSignedMerchant, false);
  assert.ok(forensics.forensicBreakdown.redFlags.length >= 3);
});

test('NPCI Forensics 2: Flags unsigned P2P intent with impersonated institutional VPA on consumer handle (@ybl)', () => {
  const uri = 'upi://pay?pa=sbihome.support@ybl&pn=SBI+Home+Loans&am=15000';
  const forensics = analyzeUpiIntentForensics(uri);

  assert.equal(forensics.detected, true);
  assert.equal(forensics.hasSuspiciousVpaHandle, true);
  assert.equal(forensics.isUnsignedP2P, true);
  assert.equal(forensics.hasHardcodedDebitAmount, true);
  assert.equal(forensics.signal, 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC');
});

test('NPCI Forensics 3: Allows signed verified merchant intent (mc=5411, sign=VALID_SIG) without fraud flag', () => {
  const uri = 'upi://pay?pa=starbucks@hdfcbank&pn=Starbucks+Coffee&mc=5411&am=350&sign=MEQCIB2K8fX9...&mode=02';
  const forensics = analyzeUpiIntentForensics(uri);

  assert.equal(forensics.detected, false);
  assert.equal(forensics.score, 0);
  assert.equal(forensics.verdict, 'safe');
  assert.equal(forensics.isSignedMerchant, true);
  assert.equal(forensics.isUnsignedP2P, false);
  assert.equal(forensics.hasSuspiciousVpaHandle, false);
});

test('NPCI Forensics 4: Text scanner integrates SIG_NPCI_UNSIGNED_COLLECT_FORENSIC and returns danger verdict', () => {
  const message = 'Your electricity bill refund of Rs 3,500 is approved. Click to claim: upi://pay?pa=bescom.refund@paytm&am=3500&tn=Electricity+Bill+Refund';
  const result = scanText(message);

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 90, `Expected score >= 90, got ${result.score}`);
  assert.equal(result.goldenRuleKey, 'upi');
  assert.ok(result.signals.some(s => s.id === 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC'));
  assert.ok(result.extracted.upi !== null);
  assert.ok(result.extracted.upi.forensicBreakdown !== undefined);
  assert.equal(result.extracted.upi.forensicBreakdown.payeeVpa, 'bescom.refund@paytm');
});

// ════════════════════════════════════════════════════════════════════════════════
// 2. CROSS-ORIGIN BRAND ASSET LEECHING & VISUAL FAVICON TRAP TESTS
// ════════════════════════════════════════════════════════════════════════════════

test('Brand Asset Theft 1: Detects hotlinked official favicon on unauthorized phishing origin with password input', () => {
  const mockDoc = {
    querySelectorAll: (sel) => {
      if (sel.includes('link[rel*="icon"]')) {
        return [{ getAttribute: (attr) => (attr === 'href' ? 'https://onlinesbi.sbi/favicon.ico' : null) }];
      }
      if (sel.includes('img[src]')) {
        return [];
      }
      if (sel.includes('input')) {
        return [{ type: 'password', name: 'user_password' }];
      }
      return [];
    }
  };

  const theft = detectCrossOriginBrandAssetTheft(mockDoc, 'random-portal-2026.com');
  assert.equal(theft.detected, true);
  assert.ok(theft.leechedBrand === 'OnlineSBI' || theft.leechedBrand === 'State Bank of India');
  assert.equal(theft.assetUrl, 'https://onlinesbi.sbi/favicon.ico');
});

test('Brand Asset Theft 2: Detects hotlinked bank logo on unauthorized phishing origin with OTP card inputs', () => {
  const mockDoc = {
    querySelectorAll: (sel) => {
      if (sel.includes('link[rel*="icon"]')) {
        return [];
      }
      if (sel.includes('img[src]')) {
        return [{ getAttribute: (attr) => (attr === 'src' ? 'https://www.hdfcbank.com/static/logo.png' : null) }];
      }
      if (sel.includes('input')) {
        return [{ type: 'text', name: 'otp_input', placeholder: 'Enter 6-digit OTP' }];
      }
      return [];
    }
  };

  const theft = detectCrossOriginBrandAssetTheft(mockDoc, 'untrusted-hdfc-reward-zone.xyz');
  assert.equal(theft.detected, true);
  assert.equal(theft.leechedBrand, 'HDFC Bank');
  assert.equal(theft.assetUrl, 'https://www.hdfcbank.com/static/logo.png');
});

test('Brand Asset Theft 3: Allows official domain hosting its own official favicon/logo (zero false positives)', () => {
  const mockDoc = {
    querySelectorAll: (sel) => {
      if (sel.includes('link[rel*="icon"]')) {
        return [{ getAttribute: () => 'https://onlinesbi.sbi/favicon.ico' }];
      }
      if (sel.includes('input')) {
        return [{ type: 'password', name: 'password' }];
      }
      return [];
    }
  };

  const theft = detectCrossOriginBrandAssetTheft(mockDoc, 'onlinesbi.sbi');
  assert.equal(theft.detected, false);
});

test('Brand Asset Theft 4: Risk Engine emits SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT and blocks with score >= 85', () => {
  const domSignals = {
    brandAssetTheft: {
      detected: true,
      leechedBrand: 'State Bank of India',
      assetUrl: 'https://sbi.co.in/logo.png'
    }
  };

  const verdict = calculateRisk(
    'https://claim-reward-xyz.top/login',
    [],
    null,
    domSignals,
    null,
    null,
    null,
    null,
    1.0,
    []
  );

  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85, `Expected score >= 85, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT'));
});

// ════════════════════════════════════════════════════════════════════════════════
// 3. LUHN CARD VALIDATION & HONEY-TOKEN POISONING TESTS
// ════════════════════════════════════════════════════════════════════════════════

test('Luhn Guard 1: isLuhnValidCard validates standard cards and rejects invalid numbers', () => {
  // Valid Visa test card
  assert.equal(isLuhnValidCard('4000000000000002'), true);
  // Valid sample Visa card
  assert.equal(isLuhnValidCard('4532015112830366'), true);
  // Invalid Luhn checksum
  assert.equal(isLuhnValidCard('4000000000000001'), false);
  // Too short
  assert.equal(isLuhnValidCard('1234'), false);
  // Null / empty
  assert.equal(isLuhnValidCard(''), false);
  assert.equal(isLuhnValidCard(null), false);
});

test('Luhn Guard 2: poisonInputWithHoneyToken replaces real card with 4000000000000002 and OTP with 000000', () => {
  // Real card number gets poisoned to safe test card
  const poisonedCard = poisonInputWithHoneyToken('4532015112830366', 'card');
  assert.equal(poisonedCard, '4000000000000002');

  // Real OTP gets poisoned to 000000
  const poisonedOtp = poisonInputWithHoneyToken('847291', 'otp');
  assert.equal(poisonedOtp, '000000');

  // Real PIN gets poisoned to 000000
  const poisonedPin = poisonInputWithHoneyToken('1234', 'pin');
  assert.equal(poisonedPin, '000000');
});

test('Luhn Guard 3: detectSensitiveInputTrap catches 16-digit card and OTP in untrusted context', () => {
  // 1. Valid card entered on untrusted page
  const cardTrap = detectSensitiveInputTrap('4532015112830366', { type: 'text', name: 'cardNumber' }, true);
  assert.equal(cardTrap.isSensitive, true);
  assert.equal(cardTrap.isTrap, true);
  assert.equal(cardTrap.type, 'card');
  assert.equal(cardTrap.honeyToken, '4000000000000002');
  assert.equal(cardTrap.signal, 'SIG_REALTIME_KEYLOGGER_HONEYTOKEN_TRIPPED');

  // 2. 6-digit OTP entered into an OTP input on untrusted page
  const otpTrap = detectSensitiveInputTrap('938472', { type: 'text', name: 'otp' }, true);
  assert.equal(otpTrap.isSensitive, true);
  assert.equal(otpTrap.isTrap, true);
  assert.equal(otpTrap.honeyToken, '000000');

  // 3. Trusted context should never flag a trap
  const safeResult = detectSensitiveInputTrap('4532015112830366', { type: 'text', name: 'cardNumber' }, false);
  assert.equal(safeResult.isTrap, false);
});

// ════════════════════════════════════════════════════════════════════════════════
// 4. ANTI-DOXXING WEBRTC & SURVEILLANCE TRAP TESTS
// ════════════════════════════════════════════════════════════════════════════════

test('Surveillance Trap 1: detectDigitalArrestSurveillanceTrap flags camera/mic requests on non-gov domain', () => {
  const pageText = 'Urgent: Supreme Court Video Courtroom hearing. CBI Cyber Crime Cell investigation. Connect webcam and microphone immediately.';
  const trap = detectDigitalArrestSurveillanceTrap(pageText, ['camera', 'microphone'], 'fake-courtroom-portal.xyz');

  assert.equal(trap.detected, true);
  assert.equal(trap.signal, 'SIG_SURVEILLANCE_EXTORTION_TRAP');
  assert.equal(trap.score, 90);
  assert.equal(trap.verdict, 'danger');
  assert.match(trap.reason, /Digital Arrest surveillance extortion trap/i);
});

test('Surveillance Trap 2: Legitimate government domain (.gov.in / .nic.in) is never flagged', () => {
  const pageText = 'Supreme Court of India virtual hearing and e-filing video courtroom.';
  const trap = detectDigitalArrestSurveillanceTrap(pageText, ['camera', 'microphone'], 'sci.gov.in');

  assert.equal(trap.detected, false);
});

// ════════════════════════════════════════════════════════════════════════════════
// 5. RISK ENGINE OVERRIDES & MULTILINGUAL CITIZEN ADVISORIES TESTS
// ════════════════════════════════════════════════════════════════════════════════

test('Risk Engine Overrides: All 4 new signals enforce Hard Override danger verdicts (Score >= 85-90)', () => {
  const testSignals = [
    { signal: 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC', minScore: 90 },
    { signal: 'SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT', minScore: 85 },
    { signal: 'SIG_REALTIME_KEYLOGGER_HONEYTOKEN_TRIPPED', minScore: 90 },
    { signal: 'SIG_SURVEILLANCE_EXTORTION_TRAP', minScore: 90 }
  ];

  for (const { signal, minScore } of testSignals) {
    const rawSignals = [{ id: signal, score: minScore }];
    const verdict = calculateRisk(
      'https://suspicious-test-origin.xyz/page',
      rawSignals,
      null,
      null,
      null,
      null,
      null,
      null,
      1.0,
      []
    );

    assert.equal(verdict.action, 'block', `Expected block action for ${signal}`);
    assert.equal(verdict.severity, 'danger', `Expected danger severity for ${signal}`);
    assert.ok(verdict.score >= minScore, `Expected score >= ${minScore} for ${signal}, got ${verdict.score}`);
  }
});

test('Multilingual Coverage: All 4 new signals have complete, valid translations across en, ta, hi, te', () => {
  const signals = [
    'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC',
    'SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT',
    'SIG_REALTIME_KEYLOGGER_HONEYTOKEN_TRIPPED',
    'SIG_SURVEILLANCE_EXTORTION_TRAP'
  ];

  const langs = ['en', 'ta', 'hi', 'te'];

  for (const sig of signals) {
    for (const lang of langs) {
      const text = getText(lang, `REASON_PLAIN.${sig}`);
      assert.ok(text && text.length > 10, `Missing translation for ${sig} in ${lang}`);
    }

    // Verify golden rule mapping
    const ruleKey = goldenRuleForSignal(sig);
    assert.ok(['upi', 'digital_arrest', 'otp_password'].includes(ruleKey), `Invalid golden rule key ${ruleKey} for ${sig}`);

    // Verify messages.en.js template function
    const enReason = t(sig);
    assert.ok(enReason && enReason.length > 10, `Missing English template for ${sig}`);
  }
});
