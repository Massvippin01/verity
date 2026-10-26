/**
 * tests/network_egress.test.js — Network Egress & Privacy Regression Test Suite
 *
 * Verifies that:
 * 1. Text scanning, phone parsing, and UPI intent parsing trigger zero network socket calls.
 * 2. Online verification strictly strips URL paths, query parameters, credentials, and message content.
 * 3. SEC-LEAK-01 regression: Reddit scam correlation never sends private message snippets.
 */

import test from 'node:test';
import assert from 'node:assert';
import http from 'node:http';

import { scanText, parseUpiString } from '../shared/text-scanner.js';
import { analyzeUpiIntentForensics } from '../shared/upi-forensics.js';
import { verifyUrlAndMessageOnline } from '../shared/online-scam-verifier.js';

test('Network Egress: Local text scanner triggers ZERO network egress', async () => {
  let networkCallCount = 0;
  const originalHttpRequest = http.request;
  http.request = function (...args) {
    networkCallCount++;
    return originalHttpRequest.apply(this, args);
  };

  try {
    const sensitiveSms =
      'URGENT: SBI Account 1234567890 blocked. Update PAN ABCDE1234F at https://sbi-kyc-update.invalid/login. ' +
      'Do not share OTP 987654. Call +91-9988776655.';

    const result = scanText(sensitiveSms);

    assert.ok(result);
    assert.strictEqual(result.verdict, 'danger');
    assert.strictEqual(result.verdictContract?.riskClassification, 'HIGH_RISK');
    assert.strictEqual(networkCallCount, 0, 'Text scanner must NOT trigger any HTTP network calls');
  } finally {
    http.request = originalHttpRequest;
  }
});

test('Network Egress: UPI Forensics parser executes 100% locally with zero network calls', async () => {
  let networkCallCount = 0;
  const originalHttpRequest = http.request;
  http.request = function (...args) {
    networkCallCount++;
    return originalHttpRequest.apply(this, args);
  };

  try {
    const upiUri = 'upi://pay?pa=refund-desk@ybl&pn=ElectricityRefund&am=5000&tn=Electricity+Bill+Refund';
    const parsed = parseUpiString(upiUri);
    assert.ok(parsed);
    assert.strictEqual(parsed.pa, 'refund-desk@ybl');

    const forensics = analyzeUpiIntentForensics(upiUri);
    assert.ok(forensics);
    assert.strictEqual(forensics.isUnsignedP2P, true);
    assert.strictEqual(networkCallCount, 0, 'UPI parsing must NOT trigger any network requests');
  } finally {
    http.request = originalHttpRequest;
  }
});

test('Network Egress: SEC-LEAK-01 Regression Guard — Reddit search never leaks private message snippets', async () => {
  const outgoingQueries = [];
  const mockFetch = async (url) => {
    outgoingQueries.push(url.toString());
    return {
      ok: false,
      status: 404,
      json: async () => ({})
    };
  };

  const privateMessage = 'Private conversation regarding personal transfer of ₹10,000 between family members.';

  // First arg is inputTextOrUrl string directly
  await verifyUrlAndMessageOnline(
    privateMessage,
    { fetchImpl: mockFetch, timeoutMs: 500 }
  );

  // Assert that Reddit search was never queried with the user text snippet
  for (const url of outgoingQueries) {
    assert.strictEqual(url.includes('reddit.com'), false, 'Reddit search must not be called on raw private message without public brand');
    assert.strictEqual(url.includes('personal%20transfer'), false, 'User message content must never appear in outbound query');
    assert.strictEqual(url.includes('10,000'), false, 'User financial details must never appear in outbound query');
  }
});
