import test from 'node:test';
import assert from 'node:assert/strict';
import { detectHomographAttack, decodePunycodeHostname, normalizeConfusables, isMixedScriptLabel } from '../background/homograph-detector.js';
import { detectTyposquatting } from '../background/brand-detector.js';
import { calculateRisk } from '../background/risk-engine.js';

const SAMPLE_BRANDS = [
  {
    name: 'Apple',
    domains: ['apple.com', 'icloud.com'],
    variants: ['apple-id', 'appleid']
  },
  {
    name: 'PayPal',
    domains: ['paypal.com', 'paypal.me'],
    variants: ['pay-pal', 'paypal-security']
  },
  {
    name: 'Google',
    domains: ['google.com', 'google.co.in'],
    variants: ['google-security', 'gogle']
  }
];

test('Punycode Decoder: correctly decodes RFC 3492 punycode hostnames', () => {
  // Cyrillic 'а' (\u0430) + 'pple'
  const decoded = decodePunycodeHostname('xn--pple-43d.com');
  assert.equal(decoded, 'аpple.com');
  assert.equal(decoded.charCodeAt(0), 0x0430, 'First letter should be Cyrillic small letter a');
});

test('Confusable Normalizer: maps lookalike Cyrillic & Greek characters to Latin ASCII', () => {
  // Cyrillic 'а' -> 'a'
  const normalized = normalizeConfusables('аpple.com');
  assert.equal(normalized, 'apple.com');

  // Cyrillic 'о' (\u043E) in 'gооgle.com'
  const normGoogle = normalizeConfusables('g\u043E\u043Egle.com');
  assert.equal(normGoogle, 'google.com');

  // Punycode 'xn--pple-43d.com' -> 'apple.com'
  const normPunycode = normalizeConfusables('xn--pple-43d.com');
  assert.equal(normPunycode, 'apple.com');
});

test('Mixed Script Detection: catches mixing Latin with Cyrillic or Greek in one label', () => {
  assert.ok(isMixedScriptLabel('xn--pple-43d'), 'Mixed Latin/Cyrillic should be flagged');
  assert.ok(isMixedScriptLabel('аpple'), 'Mixed Latin/Cyrillic should be flagged');
  assert.ok(!isMixedScriptLabel('apple'), 'Pure Latin should not be flagged');
  assert.ok(!isMixedScriptLabel('com'), 'Pure Latin should not be flagged');
});

test('Homograph Detection: detects Cyrillic Apple spoof xn--pple-43d.com', () => {
  const signal = detectHomographAttack('https://xn--pple-43d.com/login', SAMPLE_BRANDS);
  assert.equal(signal.triggered, true, 'Spoofed Apple domain must trigger');
  assert.equal(signal.id, 'RULE_HOMOGRAPH_ATTACK');
  assert.equal(signal.score, 85);
  assert.equal(signal.params.brand, 'Apple');
});

test('Homograph Detection: legitimate domain apple.com is NOT flagged', () => {
  const signal = detectHomographAttack('https://www.apple.com/shop', SAMPLE_BRANDS);
  assert.equal(signal.triggered, false, 'Official Apple domain must not trigger');
});

test('Typosquatting Integration: normalizes confusables before Levenshtein distance', () => {
  // Paypa1 with Cyrillic а in place of second a: paypа1.com
  const signal = detectTyposquatting('https://payp\u04301.com/verify', SAMPLE_BRANDS);
  assert.equal(signal.triggered, true, 'Confusable typosquat must trigger');
  assert.equal(signal.id, 'BRAND_TYPOSQUATTING');
  assert.equal(signal.params.brand, 'PayPal');
});

test('Convergence Integration: Homograph signal paired with DOM credential form reaches BLOCK', () => {
  const homographSignal = detectHomographAttack('https://xn--pple-43d.com/login', SAMPLE_BRANDS);
  const domSignals = {
    hasCredentialCollection: true,
    hasPasswordInput: true,
    loginFormCount: 1
  };
  const verdict = calculateRisk('https://xn--pple-43d.com/login', [homographSignal], null, domSignals);
  assert.equal(verdict.action, 'block', 'Homograph attack requesting credentials must produce BLOCK verdict');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 70, `Score must be >= 70, got: ${verdict.score}`);
});
