import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanText, parseUpiString, extractUrls } from '../shared/text-scanner.js';
import { extractDomain, isInternalUrl } from '../popup/popup-logic.js';
import { validateMessageSender } from '../background/message-validator.js';
import brands from '../brands.json' with { type: 'json' };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------------------------
// 1. End-to-End Message Contract Handling
// ---------------------------------------------------------------------------
test('Message Contract: validateMessageSender accepts GET_TAB_VERDICT and CHECK_TEXT', () => {
  const extId = 'verity-ext-test-id';

  // 1. Popup queries GET_TAB_VERDICT
  const popupSender = {
    id: extId,
    url: `chrome-extension://${extId}/popup/popup.html`
  };

  const r1 = validateMessageSender(popupSender, extId, {
    action: 'GET_TAB_VERDICT',
    tabId: 101
  });
  assert.equal(r1.valid, true, 'GET_TAB_VERDICT from popup must be valid');

  // 2. Tab queries GET_VERDICT
  const tabSender = {
    id: extId,
    tab: { id: 101, url: 'https://onlinesbi.sbi' }
  };
  const r2 = validateMessageSender(tabSender, extId, {
    action: 'GET_VERDICT',
    tabId: 101
  });
  assert.equal(r2.valid, true, 'GET_VERDICT with valid tab must be valid');

  // 3. Quick text / link check payload
  const r3 = validateMessageSender(popupSender, extId, {
    action: 'CHECK_TEXT',
    text: 'UPI PIN enter to claim Rs 5000 cashback'
  });
  assert.equal(r3.valid, true, 'CHECK_TEXT from popup must be valid');

  // 4. Untrusted sender ID rejected
  const evilSender = { id: 'malicious-extension-id' };
  const r4 = validateMessageSender(evilSender, extId, {
    action: 'GET_TAB_VERDICT',
    tabId: 101
  });
  assert.equal(r4.valid, false, 'Untrusted sender must be rejected');
});

// ---------------------------------------------------------------------------
// 2. All 25 Sample Cyber Fraud Payloads (0% FP, 100% Scam Detection)
// ---------------------------------------------------------------------------
test('Sample Dataset: 100% Detection on Scams and 0% FP on Legitimate Portals', () => {
  const testCasesPath = path.resolve(__dirname, '../../sample_data/indian_cyber_fraud_test_cases.json');
  assert.ok(fs.existsSync(testCasesPath), 'Test cases json must exist');

  const testCases = JSON.parse(fs.readFileSync(testCasesPath, 'utf8'));
  assert.ok(testCases.length >= 25, 'Should have at least 25 test cases');

  let scamsTested = 0;
  let scamsDetected = 0;
  let legitTested = 0;
  let falsePositives = 0;

  for (const tc of testCases) {
    const isLegit = tc.category === 'legitimate_portal';
    const result = scanText(tc.input, { brandsList: brands });

    if (isLegit) {
      legitTested++;
      if (result.verdict !== 'safe') {
        falsePositives++;
      }
      assert.equal(
        result.verdict,
        'safe',
        `False Positive on ${tc.id} (${tc.input}): expected safe, got ${result.verdict} (Score: ${result.score})`
      );
      assert.equal(result.score, 0, `Legitimate portal ${tc.input} must have score 0`);
    } else {
      scamsTested++;
      if (result.verdict === 'danger') {
        scamsDetected++;
      }
      assert.equal(
        result.verdict,
        'danger',
        `Failed to detect scam ${tc.id} (${tc.input}): expected danger, got ${result.verdict} (Score: ${result.score})`
      );
      assert.ok(result.score >= 70, `Scam ${tc.id} must return score >= 70`);
    }
  }

  assert.equal(falsePositives, 0, 'Zero false positives on official Indian portals');
  assert.equal(scamsDetected, scamsTested, '100% of Indian scam test cases must be detected as danger');
});

// ---------------------------------------------------------------------------
// 3. Edge-Case URL & Input Parsing
// ---------------------------------------------------------------------------
test('Edge-Case: Malformed upi://pay strings gracefully handled', () => {
  // Empty or invalid input
  assert.equal(parseUpiString(''), null);
  assert.equal(parseUpiString(null), null);
  assert.equal(parseUpiString('not a upi string'), null);

  // Missing parameters
  const r1 = parseUpiString('upi://pay?');
  assert.ok(r1 !== null);
  assert.equal(r1.pa, '');
  assert.equal(r1.am, '');
  assert.equal(r1.isCollect, false);

  // Normal send payment without lure keywords
  const r2 = parseUpiString('upi://pay?pa=merchant@okhdfcbank&pn=Grocery&am=250&cu=INR');
  assert.ok(r2 !== null);
  assert.equal(r2.pa, 'merchant@okhdfcbank');
  assert.equal(r2.am, '250');
  assert.equal(r2.isCollect, false, 'Standard merchant pay should not trigger collect trap');

  // Deceptive collect trap with surrounding context
  const r3 = parseUpiString(
    'upi://pay?pa=fraudster@upi&pn=PrizeWinner&am=10000',
    'Congratulations you won lottery claim cashback now'
  );
  assert.ok(r3 !== null);
  assert.equal(r3.isCollect, true, 'Amount paired with receive/cashback lure must be flagged as collect trap');

  // Multi-line and encoded strings
  const r4 = parseUpiString('Click here: upi://pay?pa=scam@ybl&am=5000&tn=Refund+Approved\nThank you');
  assert.ok(r4 !== null);
  assert.equal(r4.pa, 'scam@ybl');
  assert.equal(r4.am, '5000');
  assert.equal(r4.isCollect, true);
});

test('Edge-Case: IDN Punycode and Homograph Domains', () => {
  // Punycode google spoof: xn--gogle-qqa.com
  const punyUrl = 'https://xn--gogle-qqa.com/login';
  const res = scanText(punyUrl, { brandsList: brands });
  assert.ok(res.score >= 35, 'Punycode brand spoof must trigger elevated risk score');

  // Extract domain handles punycode
  assert.equal(extractDomain(punyUrl), 'xn--gogle-qqa.com');
});

test('Edge-Case: Raw IPv4 addresses with port and path', () => {
  const ipUrl = 'http://192.168.1.100:8080/secure/update-pan';
  const res = scanText(ipUrl, { brandsList: brands });
  assert.ok(res.score >= 35, 'Raw IP URL must be flagged');
  assert.ok(res.signals.some(s => s.id === 'RULE_IP_BASED_URL'));
  assert.equal(extractDomain(ipUrl), '192.168.1.100');
});

test('Edge-Case: Internal, Data, and Blob URIs', () => {
  assert.equal(isInternalUrl('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='), true);
  assert.equal(isInternalUrl('blob:https://web.whatsapp.com/1234-5678'), true);
  assert.equal(isInternalUrl('chrome://settings'), true);
  assert.equal(isInternalUrl('chrome-extension://xyz/popup.html'), true);
  assert.equal(isInternalUrl('about:blank'), true);
  assert.equal(isInternalUrl('https://valid-website.com'), false);
});

// ---------------------------------------------------------------------------
// 4. Illegal Web / Message UPI PIN Collection across Vernacular Languages
// ---------------------------------------------------------------------------
test('Detection: Illegal UPI/ATM PIN collection triggers SIG_ILLEGAL_WEB_PIN_COLLECTION', () => {
  const englishMsg = 'Enter your 6-digit UPI PIN to claim your Rs 5000 cashback';
  const resEn = scanText(englishMsg, { brandsList: brands });
  assert.equal(resEn.verdict, 'danger');
  assert.ok(resEn.signals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION'));
  assert.equal(resEn.goldenRuleKey, 'upi');

  const hindiMsg = 'अपना 6 अंकों का UPI पिन दर्ज करें और तुरंत 2000 रुपये रिफंड पाएं';
  const resHi = scanText(hindiMsg, { brandsList: brands });
  assert.equal(resHi.verdict, 'danger');
  assert.ok(resHi.signals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION'));

  const tamilMsg = 'உங்கள் UPI பின்னை உள்ளிடவும் மற்றும் கேஷ்பேக் பெறவும்';
  const resTa = scanText(tamilMsg, { brandsList: brands });
  assert.equal(resTa.verdict, 'danger');
  assert.ok(resTa.signals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION'));

  const teluguMsg = 'నగదు బహుమతి పొందడానికి మీ UPI పిన్ నమోదు చేయండి';
  const resTe = scanText(teluguMsg, { brandsList: brands });
  assert.equal(resTe.verdict, 'danger');
  assert.ok(resTe.signals.some(s => s.id === 'SIG_ILLEGAL_WEB_PIN_COLLECTION'));
});
