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
import {
  extractDomainFromUrl,
  verifyEntityOfficialDomainOnline,
  checkDnsOverHttpsAndCloak,
  checkIcannRdapDomainAge,
  checkRedditScamCorroboration,
  verifyUrlAndMessageOnline
} from '../shared/online-scam-verifier.js';
import { detectCompromisedHostPhishing } from '../background/compromised-site-detector.js';

// ── Test 1: ChatGPT Plus Stripe Checkout returns SAFE (Score <= 15, allow) ───
test('Precision Fix 1: ChatGPT Plus Stripe UPI Checkout returns SAFE and ALLOW', () => {
  const url = 'https://pay.openai.com/c/pay/cs_live_a1b2c3d4e5f6g7h8';
  const pageText = 'Authorize payment with your app. Scan this QR code using your preferred UPI app and follow the instructions to pay. UPI is supported in multiple apps. Powered by Stripe. Billing address. ₹1,999.00/month. Terms Privacy';
  const upiUri = 'upi://pay?pa=stripe@hdfcbank&pn=OpenAI&am=1999.00&cu=INR';

  // UPI Forensics audit must be safe
  const upiForensics = analyzeUpiIntentForensics(upiUri, pageText);
  assert.equal(upiForensics.detected, false);
  assert.equal(upiForensics.score, 0);

  // Structural DOM clone graph check with only 2 links (Terms & Privacy)
  const domCloneResult = analyzeUniversalDomPhishGraph({
    totalLinks: 2,
    deadLinkRatio: 0,
    externalMediaRatio: 0.5,
    pageText,
    hasSensitiveInputs: true
  }, 'pay.openai.com');
  assert.equal(domCloneResult.detected, false);

  // Risk Engine evaluation
  const verdict = calculateRisk(url, [], null, {
    pageText,
    upiUri,
    universalDomPhishGraph: domCloneResult,
    hasPasswordInput: false,
    hasCredentialCollection: false,
    isPaymentPage: true
  });

  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.severity, 'safe');
  assert.ok(verdict.score <= 15, `Expected score <= 15, got ${verdict.score}`);
  assert.equal(verdict.signals.some(s => s.id === 'SIG_UNIVERSAL_DOM_CLONE_PHISH'), false);
  assert.equal(verdict.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'), false);
});

// ── Test 2: Stripe Hosted Domain (checkout.stripe.com) returns SAFE ─────────
test('Precision Fix 2: Stripe Checkout Hosted Domain (checkout.stripe.com) returns SAFE and ALLOW', () => {
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

// ── Test 3: Razorpay Embedded Modal returns SAFE ───────────────────────────
test('Precision Fix 3: Razorpay Embedded Checkout Modal returns SAFE and ALLOW', () => {
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

// ── Test 4: BillDesk & PayU Utility / E-Commerce Checkouts return SAFE ──────
test('Precision Fix 4: BillDesk & PayU Checkouts return SAFE and ALLOW', () => {
  const billdeskVerdict = calculateRisk('https://pgi.billdesk.com/pgidsk/pgijsp/SBICardPayment.jsp', [], null, {
    pageText: 'Powered by BillDesk. Total payable: ₹2,450.00. Select payment method: Net Banking, Debit Card, UPI.'
  });
  assert.equal(billdeskVerdict.action, 'allow');
  assert.equal(billdeskVerdict.severity, 'safe');

  const payuVerdict = calculateRisk('https://secure.payu.in/_payment', [], null, {
    pageText: 'Powered by PayU. Amount to pay: ₹1,200.00. Billing address and payment options.'
  });
  assert.equal(payuVerdict.action, 'allow');
  assert.equal(payuVerdict.severity, 'safe');
});

// ── Test 5: Honest Merchant UPI QR Code returns score 0 ─────────────────────
test('Precision Fix 5: Honest Merchant UPI QR Code returns score 0 in text scanner and forensics', () => {
  const text = 'Scan QR code to pay ₹250 for your order at Coffee Shop. Thank you for your visit!';
  const upiUri = 'upi://pay?pa=merchant@icici&pn=CoffeeShop&am=250';

  const forensics = analyzeUpiIntentForensics(upiUri, text);
  assert.equal(forensics.detected, false);
  assert.equal(forensics.score, 0);

  const scanResult = scanText(`${text} ${upiUri}`);
  assert.equal(scanResult.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'), false);
  assert.equal(scanResult.signals.some(s => s.id === 'SIG_NPCI_UNSIGNED_COLLECT_FORENSIC'), false);
});

// ── Test 6: Deceptive OLX Cashback UPI QR Scam MUST STILL BLOCK (Contrast) ──
test('Precision Fix 6: Deceptive OLX Cashback UPI QR Scam MUST STILL be blocked as DANGER (score >= 85)', () => {
  const scamText = 'Congratulations! Scan this QR code to RECEIVE ₹5,000 cashback into your account immediately. OLX buyer payment.';
  const scamUri = 'upi://pay?pa=scammer99@ybl&pn=OLXCashback&am=5000';

  const forensics = analyzeUpiIntentForensics(scamUri, scamText);
  assert.equal(forensics.detected, true);
  assert.ok(forensics.score >= 85, `Expected forensics score >= 85, got ${forensics.score}`);

  const scanResult = scanText(`${scamText} ${scamUri}`);
  assert.ok(scanResult.score >= 85, `Expected scanText score >= 85, got ${scanResult.score}`);
  assert.ok(scanResult.signals.some(s => s.id === 'SIG_UPI_QR_COLLECT_TRAP'));

  const verdict = calculateRisk('https://olx-cashback-claim2026.xyz/reward', [], null, {
    pageText: scamText,
    upiQrCollectTrap: true,
    upiQrLure: 'receive cashback'
  });
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85);
});

// ── Test 7: Illegal Web UPI PIN Harvest MUST STILL BLOCK (Contrast) ─────────
test('Precision Fix 7: Illegal Web UPI PIN Harvest MUST STILL be blocked as DANGER (score >= 90)', () => {
  const phishingPageText = 'Verify your bank account now. Enter your 6-digit UPI PIN on this page to authorize your refund.';
  const scanResult = scanText(phishingPageText);
  assert.ok(scanResult.signals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION'));
  assert.ok(scanResult.score >= 90, `Expected scanText score >= 90, got ${scanResult.score}`);

  const verdict = calculateRisk('https://sbi-refund-portal.net/login', [], null, {
    pageText: phishingPageText,
    illegalWebPinCollection: true,
    asksForUpiPinInInput: true
  });
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 90);
});

// ── Test 8: Wikidata Entity Verifier Matches Official Domain ────────────────
test('Online Verifier 1: Wikidata Entity Verifier Matches Official Domain (openai.com for OpenAI)', async () => {
  // Mock fetch simulating Wikidata API responses
  const mockFetch = async (url) => {
    if (url.includes('wbsearchentities')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          search: [{ id: 'Q105943806', label: 'OpenAI' }]
        })
      };
    }
    if (url.includes('wbgetclaims')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          claims: {
            P856: [{ mainsnak: { datavalue: { value: 'https://openai.com' } } }]
          }
        })
      };
    }
    return { ok: false, status: 404 };
  };

  const result = await verifyEntityOfficialDomainOnline('OpenAI', 'pay.openai.com', { fetchImpl: mockFetch });
  assert.equal(result.verified, true);
  assert.equal(result.matched, true);
  assert.equal(result.officialDomain, 'openai.com');
  assert.equal(result.signal, undefined);
});

// ── Test 9: Wikidata Entity Verifier Catches Domain Mismatch (Score: 92, danger) ──
test('Online Verifier 2: Wikidata Entity Verifier Flags Domain Mismatch (SIG_ONLINE_ENTITY_DOMAIN_MISMATCH)', async () => {
  const mockFetch = async (url) => {
    if (url.includes('wbsearchentities')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          search: [{ id: 'Q105943806', label: 'OpenAI' }]
        })
      };
    }
    if (url.includes('wbgetclaims')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          claims: {
            P856: [{ mainsnak: { datavalue: { value: 'https://openai.com' } } }]
          }
        })
      };
    }
    return { ok: false, status: 404 };
  };

  const result = await verifyEntityOfficialDomainOnline('OpenAI', 'chatgpt-free-premium.xyz', { fetchImpl: mockFetch });
  assert.equal(result.verified, true);
  assert.equal(result.matched, false);
  assert.equal(result.officialDomain, 'openai.com');
  assert.ok(result.signal, 'Expected mismatch signal');
  assert.equal(result.signal.id, 'SIG_ONLINE_ENTITY_DOMAIN_MISMATCH');
  assert.equal(result.signal.score, 92);
  assert.equal(result.signal.severity, 'danger');
});

// ── Test 10: Wikidata Verifier Gracefully Falls Back on Offline / Timeout ────
test('Online Verifier 3: Wikidata Verifier handles network failure without throwing', async () => {
  const failingFetch = async () => {
    throw new Error('Network offline or timeout');
  };

  const result = await verifyEntityOfficialDomainOnline('State Bank of India', 'sbi-fake.xyz', { fetchImpl: failingFetch });
  assert.equal(result.verified, false);
  assert.equal(result.matched, null);
  assert.ok(result.error);
});

// ── Test 11: DoH Inspector Detects CNAME Tunnel Cloaking ─────────────────────
test('Online Verifier 4: DoH Inspector catches CNAME tunnel cloaking (SIG_DNS_CNAME_CLOAKING_DETECTED)', async () => {
  const mockFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      Status: 0,
      Answer: [
        { type: 5, data: 'secure-tunnel-987.trycloudflare.com.' },
        { type: 1, data: '104.21.5.12' }
      ]
    })
  });

  const dohResult = await checkDnsOverHttpsAndCloak('sbi-customer-portal.top', { fetchImpl: mockFetch });
  assert.equal(dohResult.checked, true);
  assert.equal(dohResult.hasCnameCloak, true);
  assert.ok(dohResult.signals.some(s => s.id === 'SIG_DNS_CNAME_CLOAKING_DETECTED'));
});

// ── Test 12: DoH Inspector Detects Quad9 / Sinkhole IP ──────────────────────
test('Online Verifier 5: DoH Inspector catches security sinkhole IP (0.0.0.0)', async () => {
  const mockFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      Status: 0,
      Answer: [
        { type: 1, data: '0.0.0.0' }
      ]
    })
  });

  const dohResult = await checkDnsOverHttpsAndCloak('malware-distribution.xyz', { fetchImpl: mockFetch });
  assert.equal(dohResult.checked, true);
  assert.equal(dohResult.isSinkholed, true);
  assert.ok(dohResult.signals.some(s => s.id === 'SIG_DOH_MALWARE_SINKHOLE_DETECTED'));
});

// ── Test 13: ICANN RDAP Domain Age flags newly registered domains (< 14 days) ─
test('Online Verifier 6: ICANN RDAP flags newly registered domain under 14 days old', async () => {
  const fourDaysAgo = new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString();
  const mockFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      events: [
        { eventAction: 'registration', eventDate: fourDaysAgo }
      ]
    })
  });

  const rdapResult = await checkIcannRdapDomainAge('hdfc-online-kyc.xyz', { fetchImpl: mockFetch });
  assert.equal(rdapResult.checked, true);
  assert.ok(rdapResult.ageDays <= 5);
  assert.ok(rdapResult.signals.some(s => s.id === 'SIG_NEWLY_REGISTERED_DOMAIN_CAUTION'));
});

// ── Test 14: Compromised CMS Deep-Path Phish Contrast Test ──────────────────
test('Compromised CMS Detector: Detects deep-path phishing kit on compromised WordPress host', () => {
  const phishUrl = 'https://legitimate-bakery.com/wp-content/plugins/contact-form-7/sbi/login.php';
  const pageText = 'State Bank of India Personal Banking. Enter your Username, Password and OTP to proceed.';

  const result = detectCompromisedHostPhishing(phishUrl, {
    pageText,
    hasSensitiveInputs: true
  });

  assert.equal(result.detected, true);
  assert.equal(result.signal, 'SIG_COMPROMISED_CMS_HOST_PHISH');
  assert.ok(result.score >= 85, `Expected score >= 85, got ${result.score}`);
});

// ── Test 15: Unified verifyUrlAndMessageOnline on Benign Merchant (Safe) ────
test('Unified Pipeline 1: verifyUrlAndMessageOnline on legitimate ChatGPT Plus Stripe checkout returns SAFE', async () => {
  const input = 'https://pay.openai.com/c/pay/cs_live_12345 Authorize payment with your app. Powered by Stripe.';
  const verdict = await verifyUrlAndMessageOnline(input, {
    isPaymentPage: true,
    pageText: 'Authorize payment with your app. Scan this QR code using your preferred UPI app. Powered by Stripe. Billing address. Terms Privacy'
  });

  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.severity, 'safe');
  assert.ok(verdict.score <= 15);
  assert.ok(Array.isArray(verdict.onlineProofSteps));
  assert.ok(verdict.onlineProofSteps.length >= 4);
});

// ── Test 16: Unified verifyUrlAndMessageOnline flags phishing link with Entity Mismatch ──
test('Unified Pipeline 2: verifyUrlAndMessageOnline flags deceptive entity spoofing as DANGER', async () => {
  const mockFetch = async (url) => {
    if (url.includes('wbsearchentities')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ search: [{ id: 'Q105943806', label: 'OpenAI' }] })
      };
    }
    if (url.includes('wbgetclaims')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ claims: { P856: [{ mainsnak: { datavalue: { value: 'https://openai.com' } } }] } })
      };
    }
    return { ok: false, status: 404 };
  };

  const input = 'Claim free GPT-5 access now at https://chatgpt-plus-free2026.xyz/login. Enter your phone and password.';
  const verdict = await verifyUrlAndMessageOnline(input, {
    entityName: 'OpenAI',
    fetchImpl: mockFetch
  });

  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_ONLINE_ENTITY_DOMAIN_MISMATCH'));
});

// ── Test 17: Android Bridge onIncomingIntent Routing Simulation ─────────────
test('Android Bridge: onIncomingIntent correctly routes URL, payment, and message payloads', () => {
  let routedTool = null;
  let populatedValue = null;
  let scannedPayload = null;

  // Mock bridge environment
  const mockBridge = {
    onIncomingIntent: function(payload) {
      if (!payload) return;
      let data = typeof payload === 'string' ? payload : (payload.data || payload.text || payload.url || '');
      const type = (payload.type || '').toLowerCase();

      if (type === 'payment' || data.startsWith('upi://')) {
        routedTool = 'payment';
        populatedValue = data;
        scannedPayload = data;
      } else if (type === 'url' || /^https?:\/\//i.test(data.trim())) {
        routedTool = 'website';
        populatedValue = data;
        scannedPayload = data;
      } else {
        routedTool = 'message';
        populatedValue = data;
        scannedPayload = data;
      }
    }
  };

  // Case A: URL payload from Chrome share
  mockBridge.onIncomingIntent({ type: 'url', data: 'https://suspicious-parcel-hold.top' });
  assert.equal(routedTool, 'website');
  assert.equal(populatedValue, 'https://suspicious-parcel-hold.top');

  // Case B: UPI QR intent from camera or deep-link
  mockBridge.onIncomingIntent({ type: 'payment', data: 'upi://pay?pa=seller@upi&am=499' });
  assert.equal(routedTool, 'payment');
  assert.equal(populatedValue, 'upi://pay?pa=seller@upi&am=499');

  // Case C: Shared WhatsApp text message
  mockBridge.onIncomingIntent({ type: 'shared_text', data: 'Urgent: Police digital arrest notice.' });
  assert.equal(routedTool, 'message');
  assert.equal(populatedValue, 'Urgent: Police digital arrest notice.');
});
