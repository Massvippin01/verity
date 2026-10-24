import test from 'node:test';
import assert from 'node:assert/strict';

import { calculateRisk } from '../background/risk-engine.js';
import { analyzeUpiIntentForensics } from '../shared/upi-forensics.js';
import { detectUpiQrCollectTrap } from '../content/bharat-scam-detectors.js';
import { analyzeUniversalDomPhishGraph } from '../content/structural-phish-graph.js';
import { scanText } from '../shared/text-scanner.js';
import {
  isAuthorizedPaymentGatewayOrMerchant,
  isLegitimateCheckoutFlow
} from '../shared/payment-gateway-allowlist.js';

test('Precision Fix 1: ChatGPT Plus Stripe UPI Checkout returns SAFE and ALLOW with 0 false positive signals', () => {
  const url = 'https://pay.openai.com/c/pay/cs_live_a1b2c3d4e5f6g7h8';
  const pageText = 'Authorize payment with your app. Scan this QR code using your preferred UPI app and follow the instructions to pay. UPI is supported in multiple apps. Powered by Stripe. Billing address. ₹1,999.00/month. Terms Privacy';
  const upiUri = 'upi://pay?pa=stripe@hdfcbank&pn=OpenAI&am=1999.00&cu=INR';

  // 1. UPI Forensics audit must be safe
  const upiForensics = analyzeUpiIntentForensics(upiUri, pageText);
  assert.equal(upiForensics.detected, false);
  assert.equal(upiForensics.score, 0);

  // 2. Structural DOM clone graph check with only 2 links (Terms & Privacy)
  const domCloneResult = analyzeUniversalDomPhishGraph({
    totalLinks: 2,
    deadLinkRatio: 0,
    externalMediaRatio: 0.5,
    pageText,
    hasSensitiveInputs: true
  }, 'pay.openai.com');
  assert.equal(domCloneResult.detected, false);

  // 3. Full Risk Engine evaluation
  const domSignals = {
    pageText,
    upiUri,
    universalDomPhishGraph: domCloneResult,
    hasPasswordInput: false,
    hasCredentialCollection: false,
    isPaymentPage: true
  };

  const verdict = calculateRisk(url, [], null, domSignals, null, null, null);

  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.severity, 'safe');
  assert.ok(verdict.score <= 15, `Expected score <= 15, got ${verdict.score}`);
  assert.equal(verdict.signals.some(s => s.id === 'SIG_UNIVERSAL_DOM_CLONE_PHISH'), false);
  assert.equal(verdict.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'), false);
  assert.equal(verdict.signals.some(s => s.id === 'SIG_NEURAL_META_FUSION_PHISH'), false);
});

test('Precision Fix 1b: Stripe Checkout Hosted Domain (checkout.stripe.com) returns SAFE and ALLOW', () => {
  const url = 'https://checkout.stripe.com/c/pay/cs_live_xyz987';
  const pageText = 'Authorize payment with your app. Scan this QR code using your preferred UPI app. Powered by Stripe. Total due ₹1,999.00. Terms Privacy';
  const upiUri = 'upi://pay?pa=stripe@hdfcbank&pn=StripePay&am=1999.00';

  const verdict = calculateRisk(url, [], null, {
    pageText,
    upiUri,
    isPaymentPage: true
  });

  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.severity, 'safe');
  assert.ok(verdict.score <= 15, `Expected score <= 15, got ${verdict.score}`);
});

test('Precision Fix 2: Razorpay Embedded Checkout Modal returns SAFE and ALLOW', () => {
  const url = 'https://api.razorpay.com/v1/checkout/embedded';
  const pageText = 'Powered by Razorpay. Enter card details or select UPI to complete payment of ₹499. Order summary: Premium Plan. Terms Privacy';

  const verdict = calculateRisk(url, [], null, {
    pageText,
    isPaymentPage: true
  });

  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.severity, 'safe');
  assert.ok(verdict.score <= 15, `Expected score <= 15, got ${verdict.score}`);
});

test('Precision Fix 3: BillDesk & PayU Utility / E-Commerce Checkouts return SAFE and ALLOW', () => {
  const billdeskUrl = 'https://pgi.billdesk.com/pgidsk/pgijsp/SBICardPayment.jsp';
  const billdeskVerdict = calculateRisk(billdeskUrl, [], null, {
    pageText: 'Powered by BillDesk. Total payable: ₹2,450.00. Select payment method: Net Banking, Debit Card, UPI.'
  });
  assert.equal(billdeskVerdict.action, 'allow');
  assert.equal(billdeskVerdict.severity, 'safe');

  const payuUrl = 'https://secure.payu.in/_payment';
  const payuVerdict = calculateRisk(payuUrl, [], null, {
    pageText: 'Powered by PayU. Amount to pay: ₹1,200.00. Billing address and payment options.'
  });
  assert.equal(payuVerdict.action, 'allow');
  assert.equal(payuVerdict.severity, 'safe');
});

test('Precision Fix 4: Honest Merchant UPI QR Code returns score 0 in text scanner and forensics', () => {
  const text = 'Scan QR code to pay ₹250 for your order at Coffee Shop. Thank you for your visit!';
  const upiUri = 'upi://pay?pa=merchant@icici&pn=CoffeeShop&am=250';

  const forensics = analyzeUpiIntentForensics(upiUri, text);
  assert.equal(forensics.detected, false);
  assert.equal(forensics.score, 0);

  const scanResult = scanText(`${text} ${upiUri}`);
  assert.equal(scanResult.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'), false);
  assert.equal(scanResult.signals.some(s => s.id === 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC'), false);
});

test('Precision Fix 5 (Contrast Security Test): Deceptive OLX Cashback UPI QR Scam MUST STILL be blocked as DANGER (score >= 85)', () => {
  const scamText = 'Congratulations! Scan this QR code to RECEIVE ₹5,000 cashback into your account immediately. OLX buyer payment.';
  const scamUri = 'upi://pay?pa=scammer99@ybl&pn=OLXCashback&am=5000';

  const forensics = analyzeUpiIntentForensics(scamUri, scamText);
  assert.equal(forensics.detected, true);
  assert.ok(forensics.score >= 85, `Expected forensics score >= 85, got ${forensics.score}`);

  const scanResult = scanText(`${scamText} ${scamUri}`);
  assert.ok(scanResult.score >= 85, `Expected scanText score >= 85, got ${scanResult.score}`);
  assert.ok(scanResult.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'));

  // End-to-end Risk Engine test on fraudulent site
  const verdict = calculateRisk('https://olx-cashback-claim2026.xyz/reward', [], null, {
    pageText: scamText,
    upiQrCollectTrap: true,
    upiQrLure: 'receive cashback'
  });
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85, `Expected risk score >= 85, got ${verdict.score}`);
});

test('Precision Fix 6 (Contrast Security Test): Illegal Web UPI PIN Harvest MUST STILL be blocked as DANGER (score >= 90)', () => {
  const phishingPageText = 'Verify your bank account now. Enter your 6-digit UPI PIN on this page to authorize your refund.';
  const scanResult = scanText(phishingPageText);
  assert.ok(scanResult.signals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION'));
  assert.ok(scanResult.score >= 90, `Expected scanText score >= 90, got ${scanResult.score}`);

  // Risk Engine check on malicious portal
  const verdict = calculateRisk('https://sbi-refund-portal.net/login', [], null, {
    pageText: phishingPageText,
    illegalWebPinCollection: true,
    asksForUpiPinInInput: true
  });
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 90, `Expected risk score >= 90, got ${verdict.score}`);
});
