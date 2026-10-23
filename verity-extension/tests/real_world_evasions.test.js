/**
 * tests/real_world_evasions.test.js
 *
 * Real-World Battle-Hardening Test Suite:
 * Validates detection of attacker evasions including free-hosting phishing kits,
 * DOM brand spoofing, shortened links with scam lures, obfuscated Hinglish/Tanglish terms,
 * and utility/courier extortion attacks while guaranteeing 0% false positives on legitimate sites.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { scanText, isUrlShortener, normalizeEvasions } from '../shared/text-scanner.js';
import { calculateRisk } from '../background/risk-engine.js';
import { isAbusedFreeHostingOrTunnel } from '../background/rules.js';
import { detectDomBrandSpoof, HIGH_VALUE_DOM_BRANDS } from '../content/bharat-scam-detectors.js';

// ════════════════════════════════════════════════════════════════════════════════
// 1. Obfuscated Hinglish & Tanglish Scam Evasions
// ════════════════════════════════════════════════════════════════════════════════

test('Real-World Case 1: Obfuscated Hinglish OLX QR Scam with punctuated u.p.i p-i-n', () => {
  const message = 'Bhai yeh QR scan karo aur apna 4 digit u.p.i p-i-n dalo 5000rs तुरंत account me aayega';
  const result = scanText(message);

  assert.equal(result.verdict, 'danger', 'Must trigger Danger verdict');
  assert.ok(result.score >= 85, `Score must be >= 85, got ${result.score}`);
  const hasPinOrQrSignal = result.signals.some(s =>
    s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION' || s.id === 'SIG_UPI_QR_COLLECT_TRAP'
  );
  assert.ok(hasPinOrQrSignal, 'Must trigger SIG_ILLEGAL_WEB_PIN_COLLECTION or SIG_UPI_QR_COLLECT_TRAP');
});

test('Real-World Case 2: Colloquial Tanglish QR Cashback Trap with PIN prompt', () => {
  const message = 'QR code scan pannunga, 2000 rupees cashback ungal account la aayega, upi pin potu accept pannunga';
  const result = scanText(message);

  assert.equal(result.verdict, 'danger', 'Must trigger Danger verdict');
  assert.ok(result.score >= 85, `Score must be >= 85, got ${result.score}`);
  const hasPinOrQrSignal = result.signals.some(s =>
    s.id === 'SIG_UPI_QR_COLLECT_TRAP' || s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION'
  );
  assert.ok(hasPinOrQrSignal, 'Must flag Tanglish QR collect or PIN prompt');
});

test('Real-World Case 3: Dotted Obfuscation Normalizer (k.y.c, o.t.p, u.p.i, p-i-n, a.p.k)', () => {
  const raw = 'Please verify your k.y.c and enter o.t.p or download pan_update.a.p.k';
  const normalized = normalizeEvasions(raw);

  assert.ok(normalized.includes('kyc'), 'Should normalize k.y.c to kyc');
  assert.ok(normalized.includes('otp'), 'Should normalize o.t.p to otp');
  assert.ok(normalized.includes('apk'), 'Should normalize a.p.k to apk');
});

// ════════════════════════════════════════════════════════════════════════════════
// 2. Free-Hosting & Tunnel Phishing Kits
// ════════════════════════════════════════════════════════════════════════════════

test('Real-World Case 4: Vercel hosted SBI netbanking credential phishing kit', () => {
  const url = 'https://sbi-netbanking-portal.vercel.app/login';
  assert.ok(isAbusedFreeHostingOrTunnel(new URL(url).hostname), 'Must match free hosting suffix');

  const verdict = calculateRisk(url);
  assert.equal(verdict.severity, 'danger', 'Must trigger Danger severity');
  assert.ok(verdict.score >= 75, `Score must be >= 75, got ${verdict.score}`);
  const hasSignal = verdict.signals.some(s => s.id === 'SIG_FREE_HOST_CREDENTIAL_PHISH');
  assert.ok(hasSignal, 'Must emit SIG_FREE_HOST_CREDENTIAL_PHISH');
});

test('Real-World Case 5: Ngrok tunnel hosted ICICI KYC phishing kit with password input', () => {
  const url = 'https://icici-kyc-service.ngrok-free.app/update';
  assert.ok(isAbusedFreeHostingOrTunnel(new URL(url).hostname), 'Must match tunnel suffix');

  const domSignals = {
    hasPasswordInput: true,
    paymentFields: { otp: true }
  };
  const verdict = calculateRisk(url, [], null, domSignals);
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 75, `Score must be >= 75, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_FREE_HOST_CREDENTIAL_PHISH'));
});

test('Real-World Case 6: Cloudflare Pages phishing kit with UPI verification lure', () => {
  const url = 'https://phonepe-rewards.pages.dev/claim-cashback';
  assert.ok(isAbusedFreeHostingOrTunnel(new URL(url).hostname), 'Must match pages.dev');

  const result = scanText(`Claim cashback on PhonePe: ${url}`);
  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 75, `Score must be >= 75, got ${result.score}`);
  assert.ok(result.signals.some(s => s.id === 'SIG_FREE_HOST_CREDENTIAL_PHISH'));
});

// ════════════════════════════════════════════════════════════════════════════════
// 3. DOM Title / Heading Brand Impersonation Trap
// ════════════════════════════════════════════════════════════════════════════════

test('Real-World Case 7: Innocent domain spoofing State Bank of India in Title with password field', () => {
  const url = 'https://india-portal-2026.com/auth';
  const domSignals = {
    pageTitle: 'State Bank of India - Personal Banking',
    hasPasswordInput: true
  };

  const verdict = calculateRisk(url, [], null, domSignals);
  assert.equal(verdict.severity, 'danger', 'Must trigger Danger severity');
  assert.ok(verdict.score >= 85, `Score must be >= 85 (Hard Override), got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_DOM_BRAND_IMPERSONATION'));
});

test('Real-World Case 8: Innocent domain claiming HDFC Bank NetBanking Portal with sensitive input', () => {
  const url = 'https://national-services-center.org/login';
  const domSignals = {
    headingText: 'HDFC Bank NetBanking Portal',
    hasPasswordInput: true
  };

  const verdict = calculateRisk(url, [], null, domSignals);
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85, `Score must be >= 85, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_DOM_BRAND_IMPERSONATION'));
});

test('Real-World Case 9: detectDomBrandSpoof unit detector on mock DOM tree', () => {
  const mockDoc = {
    title: 'Punjab National Bank - Internet Banking',
    querySelectorAll: (sel) => {
      if (sel === 'input') {
        return [{ type: 'password', name: 'pnb_pwd' }];
      }
      return [];
    }
  };

  const spoofed = detectDomBrandSpoof(mockDoc, 'unauthorized-pnb-login.xyz');
  assert.equal(spoofed.detected, true);
  assert.equal(spoofed.brand, 'Punjab National Bank');

  const legitimate = detectDomBrandSpoof(mockDoc, 'netpnb.com');
  assert.equal(legitimate.detected, false);
});

// ════════════════════════════════════════════════════════════════════════════════
// 4. Electricity Bill & IndiaPost Smishing Traps
// ════════════════════════════════════════════════════════════════════════════════

test('Real-World Case 10: BESCOM Electricity Disconnection SMS with bit.ly link', () => {
  const message = 'Dear customer your electricity power will be disconnected tonight at 9:30 PM by electricity officer. Please update bill: https://bit.ly/bescom-bill-pay';
  const result = scanText(message);

  assert.equal(result.verdict, 'danger', 'Must trigger Danger');
  assert.ok(result.score >= 85, `Score must be >= 85, got ${result.score}`);
  assert.ok(result.signals.some(s => s.id === 'SIG_UTILITY_BILL_EXTORTION'), 'Must flag utility extortion');
  assert.ok(result.signals.some(s => s.id === 'SIG_DECEPTIVE_SHORTENER_LURE'), 'Must flag deceptive shortener lure');
});

test('Real-World Case 11: TNEB power cut SMS with tinyurl.com link', () => {
  const message = 'TNEB Alert: Your power will be disconnected immediately due to unpaid bijli bill. Pay here: https://tinyurl.com/tneb-pay';
  const result = scanText(message);

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 85);
  assert.ok(result.signals.some(s => s.id === 'SIG_UTILITY_BILL_EXTORTION'));
  assert.ok(result.signals.some(s => s.id === 'SIG_DECEPTIVE_SHORTENER_LURE'));
});

test('Real-World Case 12: IndiaPost warehouse incomplete address SMS with tinyurl.com', () => {
  const message = 'India Post: Your package arrived at warehouse but could not be delivered due to incomplete address. Update address within 12 hours: https://tinyurl.com/indiapost-addr';
  const result = scanText(message);

  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 80, `Score must be >= 80, got ${result.score}`);
  assert.ok(result.signals.some(s => s.id === 'SIG_FAKE_PARCEL_DELIVERY_LURE'), 'Must flag fake parcel delivery lure');
  assert.ok(result.signals.some(s => s.id === 'SIG_DECEPTIVE_SHORTENER_LURE'));
});

test('Real-World Case 13: Neutral Standalone Shortener Link without Scam Context (Caution)', () => {
  const message = 'https://bit.ly/my-tech-blog-post';
  const result = scanText(message);

  assert.equal(result.verdict, 'caution', 'Neutral shortener link must return Caution');
  assert.ok(result.score >= 35 && result.score < 70, `Score must be in caution band [35, 69], got ${result.score}`);
  assert.ok(result.signals.some(s => s.id === 'SIG_URL_SHORTENER_CAUTION'));
});

// ════════════════════════════════════════════════════════════════════════════════
// 5. Zero False Positives on Legitimate Sites
// ════════════════════════════════════════════════════════════════════════════════

test('Real-World Case 14: Legitimate developer site on Vercel (nextjs-docs.vercel.app) remains SAFE (0% FP)', () => {
  const url = 'https://nextjs-docs.vercel.app';
  const verdict = calculateRisk(url);

  assert.equal(verdict.severity, 'safe', 'Legitimate documentation on Vercel must be Safe');
  assert.ok(verdict.score <= 25, `Score must be <= 25, got ${verdict.score}`);
  assert.equal(verdict.signals.some(s => s.id === 'SIG_FREE_HOST_CREDENTIAL_PHISH'), false);
});

test('Real-World Case 15: Official State Bank of India & India Post portals remain SAFE (0% FP)', () => {
  const sbiUrl = 'https://onlinesbi.sbi';
  const sbiSignals = {
    pageTitle: 'State Bank of India - Personal Banking',
    hasPasswordInput: true
  };
  const sbiVerdict = calculateRisk(sbiUrl, [], null, sbiSignals);
  assert.equal(sbiVerdict.severity, 'safe', 'Official SBI portal must remain Safe');
  assert.equal(sbiVerdict.score, 0, 'Official SBI portal score must be 0');
  assert.equal(sbiVerdict.signals.some(s => s.id === 'SIG_DOM_BRAND_IMPERSONATION'), false);

  const postUrl = 'https://indiapost.gov.in';
  const postSignals = {
    pageTitle: 'India Post, Ministry of Communications, Government of India',
    hasPasswordInput: false
  };
  const postVerdict = calculateRisk(postUrl, [], null, postSignals);
  assert.equal(postVerdict.severity, 'safe', 'Official India Post portal must remain Safe');
  assert.equal(postVerdict.score, 0);
  assert.equal(postVerdict.signals.some(s => s.id === 'SIG_DOM_BRAND_IMPERSONATION'), false);
});
