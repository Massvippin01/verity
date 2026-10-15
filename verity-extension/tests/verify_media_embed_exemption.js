import test from 'node:test';
import assert from 'node:assert/strict';

function createRecursiveMock() {
  const fn = () => {};
  const handler = {
    get(target, prop) {
      if (prop === 'then' || prop === Symbol.toStringTag) return undefined;
      if (prop === 'getURL') return (p) => 'http://localhost/' + p;
      if (!(prop in target)) {
        target[prop] = new Proxy((...args) => Promise.resolve({}), handler);
      }
      return target[prop];
    },
    apply(target, thisArg, argumentsList) {
      return Promise.resolve({});
    }
  };
  return new Proxy(fn, handler);
}

globalThis.chrome = createRecursiveMock();
globalThis.chrome.runtime.id = 'test-id';
globalThis.chrome.runtime.getURL = (p) => 'http://localhost/' + p;
globalThis.fetch = async () => ({ ok: true, json: async () => [] });

const { analyzePaymentPage, isEmbeddedMediaHost } = await import('../background/payment-detector.js');
const { calculateRisk } = await import('../background/risk-engine.js');
const { isTrustedTopDomain } = await import('../background/rules.js');
const { isAllowlistedDomain } = await import('../shared/legit-domains.js');
const { isSafeAllowlistedOrTopDomain } = await import('../service_worker.js');
const paymentBrands = (await import('../payment-brands.json', { with: { type: 'json' } })).default;

test('Media Embed Exemption 1: Exact User URL (youtube-nocookie.com/embed/UsmiRIozzvw) discussing PhonePe must ALLOW (Score 0, 0 Reasons)', () => {
  const url = 'https://www.youtube-nocookie.com/embed/UsmiRIozzvw';

  // 1. Verify domain trust recognition
  assert.equal(isEmbeddedMediaHost('www.youtube-nocookie.com'), true, 'Must identify as embedded media host');
  assert.equal(isTrustedTopDomain('www.youtube-nocookie.com'), true, 'Must identify as trusted top domain');
  assert.equal(isAllowlistedDomain(url), true, 'Must identify as allowlisted domain');
  assert.equal(isSafeAllowlistedOrTopDomain(url), true, 'Service worker must recognize as safe top domain');

  // 2. Simulated DOM signals from an embedded video referencing PhonePe
  const domSignals = {
    isTrustedDomain: true,
    pageTitle: 'How to Setup PhonePe UPI in 2026 - Complete Tutorial',
    pageText: 'Welcome to this video tutorial on PhonePe UPI. In this video, we review how PhonePe handles payments, cashback, and transactions.',
    headingText: 'PhonePe UPI Video Tutorial',
    structuralText: 'PhonePe UPI Video Tutorial YouTube video player',
    claimedProviders: ['PhonePe'],
    paymentFields: {},
    hasPaymentForm: false,
    hasPasswordInput: false,
    hasCredentialCollection: false
  };

  // 3. Payment Detector analysis
  const paymentAnalysis = analyzePaymentPage(url, domSignals, paymentBrands);
  console.log('\n--- Case 1: Exact User Failure URL (youtube-nocookie.com/embed/UsmiRIozzvw) ---');
  console.log('Payment Analysis:', paymentAnalysis);
  assert.equal(paymentAnalysis, null, 'Payment detector MUST return null on embedded media without payment inputs');

  // 4. Full Risk Engine Evaluation
  const verdict = calculateRisk(url, [], null, domSignals, null, null, paymentAnalysis);
  console.log('Score:', verdict.score);
  console.log('Action:', verdict.action);
  console.log('Severity:', verdict.severity);
  console.log('Reasons Count:', verdict.reasons.length);

  assert.equal(verdict.score, 0, 'Risk score on official YouTube embed must be strictly 0');
  assert.equal(verdict.action, 'allow', 'Action must be "allow"');
  assert.equal(verdict.severity, 'safe', 'Severity must be "safe"');
  assert.equal(verdict.reasons.length, 0, 'Reasons must be empty (0 false alarms)');
});

test('Media Embed Exemption 2: Official YouTube video page (youtube.com/watch?v=...) mentioning multiple brands', () => {
  const url = 'https://www.youtube.com/watch?v=UsmiRIozzvw';

  const domSignals = {
    isTrustedDomain: true,
    pageTitle: 'Fintech Comparison: PhonePe vs Google Pay vs Paytm vs Razorpay',
    pageText: 'Comparing the top Indian payment gateways and apps: PhonePe, Paytm, Google Pay, Razorpay, and HDFC Bank NetBanking.',
    headingText: 'Fintech Gateway Comparison',
    claimedProviders: ['PhonePe', 'Paytm', 'Google Pay', 'Razorpay', 'HDFC Bank'],
    paymentFields: {},
    hasPaymentForm: false,
    hasPasswordInput: false
  };

  const paymentAnalysis = analyzePaymentPage(url, domSignals, paymentBrands);
  assert.equal(paymentAnalysis, null, 'analyzePaymentPage must return null for official YouTube host without payment inputs');

  const verdict = calculateRisk(url, [], null, domSignals, null, null, paymentAnalysis);
  assert.equal(verdict.score, 0);
  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.severity, 'safe');
});

test('Media Embed Exemption 3: Vimeo & Dailymotion embeds mentioning Stripe and PayPal', () => {
  const vimeoUrl = 'https://player.vimeo.com/video/987654321';
  assert.equal(isEmbeddedMediaHost('player.vimeo.com'), true);
  assert.equal(isTrustedTopDomain('player.vimeo.com'), true);

  const domSignals = {
    isTrustedDomain: true,
    pageTitle: 'Integrating Stripe Checkout and PayPal - Web Dev Masterclass',
    pageText: 'Learn how to accept payments using Stripe checkout and PayPal smart buttons.',
    claimedProviders: ['Stripe', 'PayPal'],
    paymentFields: {},
    hasPaymentForm: false
  };

  const paymentAnalysis = analyzePaymentPage(vimeoUrl, domSignals, paymentBrands);
  assert.equal(paymentAnalysis, null);

  const verdict = calculateRisk(vimeoUrl, [], null, domSignals, null, null, paymentAnalysis);
  assert.equal(verdict.score, 0);
  assert.equal(verdict.action, 'allow');
});

test('Media Embed Exemption 4: Educational blog / Tech review mentioning PhonePe without payment inputs must NOT trigger brand mismatch', () => {
  const blogUrl = 'https://tech-news-daily.org/phonepe-upi-market-share-2026';

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'PhonePe Crosses 50% Market Share in UPI Payments',
    pageText: 'PhonePe continues to lead digital transactions across India, processing over 7 billion UPI transactions monthly.',
    headingText: 'PhonePe Market Analysis',
    claimedProviders: ['PhonePe'],
    paymentFields: {},
    hasPaymentForm: false,
    hasPasswordInput: false,
    hasCredentialCollection: false
  };

  const paymentAnalysis = analyzePaymentPage(blogUrl, domSignals, paymentBrands);
  assert.equal(paymentAnalysis, null, 'Blog with casual brand mention and no payment inputs must NOT trigger payment detector');

  const verdict = calculateRisk(blogUrl, [], null, domSignals, null, null, paymentAnalysis);
  console.log('\n--- Case 4: Educational Blog Mentioning PhonePe ---');
  console.log('Score:', verdict.score, 'Action:', verdict.action);
  assert.ok(verdict.score <= 30, `Score must be <= 30 (SAFE / allow), got ${verdict.score}`);
  assert.equal(verdict.action, 'allow');
  assert.ok(!verdict.signals.some(s => s.id === 'SIG_PAYMENT_BRAND_MISMATCH' || s.id === 'PAYMENT_FAKE_PROVIDER'));
});

test('Media Embed Exemption 5: Genuine Cloned / Fake PhonePe Gateway with actual payment inputs on attacker domain must BLOCK (Score >= 85)', () => {
  const fakeGatewayUrl = 'https://fake-phonepe-pay.xyz/checkout';

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'PhonePe Secure Payment Gateway',
    pageText: 'Enter your Card Number and CVV or UPI ID to complete your payment of ₹1,499 with PhonePe.',
    structuralText: 'PhonePe Secure Payment Gateway card number cvv upi pay now',
    headingText: 'PhonePe Checkout',
    buttonLabels: 'Pay with PhonePe',
    claimedProviders: ['PhonePe'],
    paymentFields: { card: true, cvv: true, upi: true },
    hasPaymentForm: true,
    hasPasswordInput: false,
    hasCredentialCollection: true
  };

  const paymentAnalysis = analyzePaymentPage(fakeGatewayUrl, domSignals, paymentBrands);
  assert.ok(paymentAnalysis, 'Payment analysis must run on attacker page with active payment inputs');
  assert.equal(paymentAnalysis.claimedProvider, 'PhonePe');
  assert.equal(paymentAnalysis.domainMismatch, true);
  assert.ok(paymentAnalysis.structuredReasons.some(r => r.id === 'SIG_PAYMENT_BRAND_MISMATCH'));
  assert.ok(paymentAnalysis.structuredReasons.some(r => r.id === 'PAYMENT_FAKE_PROVIDER'));

  const verdict = calculateRisk(fakeGatewayUrl, [], null, domSignals, null, null, paymentAnalysis);
  console.log('\n--- Case 5: Attacker Cloned PhonePe Gateway with Payment Inputs ---');
  console.log('Score:', verdict.score, 'Action:', verdict.action, 'Severity:', verdict.severity);
  console.log('Reasons:\n ', verdict.reasons.join('\n  '));

  assert.ok(verdict.score >= 85, `Score must be >= 85, got ${verdict.score}`);
  assert.equal(verdict.action, 'block', `Action must be "block", got ${verdict.action}`);
  assert.equal(verdict.severity, 'danger', `Severity must be "danger", got ${verdict.severity}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_PAYMENT_BRAND_MISMATCH'));
});

test('Media Embed Exemption 6: Hostile injection inside embed containing active payment form is NOT exempt', () => {
  const url = 'https://www.youtube-nocookie.com/embed/malicious-inject';

  const domSignals = {
    isTrustedDomain: false,
    pageTitle: 'Payment Verification',
    pageText: 'Enter your credit card number and CVV to verify your age.',
    paymentFields: { card: true, cvv: true },
    hasPaymentForm: true
  };

  const paymentAnalysis = analyzePaymentPage(url, domSignals, paymentBrands);
  assert.ok(paymentAnalysis !== null, 'If actual credit card fields are injected, detector must not blindly ignore payment fields');
  assert.ok(paymentAnalysis.paymentFields.card === true);
});
