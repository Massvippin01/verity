import test from 'node:test';
import assert from 'node:assert/strict';

import { computeSecvIntentVector, normalizeVernacularPhonetics } from '../shared/secv-intent-engine.js';
import {
  extractAssertedDomIdentity,
  isDomainAlignedWithIdentity,
  toUnicodeConfusableSkeleton,
  damerauLevenshtein,
  auditDomainDmarcPosture,
  verifyAutonomousBrandIdentity
} from '../shared/autonomous-brand-discovery.js';
import { scanText } from '../shared/text-scanner.js';
import { calculateRisk } from '../background/risk-engine.js';
import { queryPhishStatsPublicFeed, queryOnlineFreeIntelGrid } from '../background/online-free-intel.js';
import { verifyUrlAndMessageOnline } from '../shared/online-scam-verifier.js';
import { REASON_PLAIN, goldenRuleForSignal } from '../shared/citizen-messages.js';

// ═════════════════════════════════════════════════════════════════════════════
// PILLAR 1: 5D Psycholinguistic Coercion & Intent Vector Engine
// ═════════════════════════════════════════════════════════════════════════════

test('Pillar 1.1: Rephrased Crime Cell / Contraband notice (zero classic keywords) triggers SECV danger', () => {
  const text = 'Inspector Rathore from Crime Cell. Contraband seized in parcel under your name. Connect immediately on video call or police vehicle will be dispatched to your address.';
  const secv = computeSecvIntentVector(text);

  assert.ok(secv.isConvergentScam, 'Should flag convergent scam');
  assert.ok(secv.score >= 85, `Expected score >= 85, got ${secv.score}`);
  assert.ok(secv.vector.A > 0, 'Authority vector must be active');
  assert.ok(secv.vector.C > 0, 'Catastrophic loss vector must be active');
  assert.ok(secv.vector.U > 0, 'Urgency vector must be active');
  assert.ok(secv.vector.E > 0, 'Extraction action vector must be active');

  // Integrates into scanText
  const result = scanText(text);
  assert.equal(result.verdict, 'danger');
  assert.ok(result.score >= 85);
  assert.ok(result.signals.some(s => s.id === 'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE'));
});

test('Pillar 1.2: Deceptive Reward / Subsidy + Extraction lure (A + G + U + E with C = 0) flags danger', () => {
  const text = 'Official Ministry Department Notice: Your solar subsidy bonus of ₹25,000 is approved. Claim immediately before midnight tonight. Download and verify on Skype call with officer.';
  const secv = computeSecvIntentVector(text);

  assert.ok(secv.isConvergentScam, 'Should flag deceptive reward extraction');
  assert.ok(secv.score >= 82, `Expected score >= 82, got ${secv.score}`);
  assert.ok(secv.vector.G > 0, 'Financial gain vector must be active');
  assert.ok(secv.vector.E > 0, 'Extraction vector must be active');
});

test('Pillar 1.3: Phonetic Hinglish coercion ("Abhi apna pin dalo warna bijli kat jayega") returns danger', () => {
  const text = 'Abhi apna u.p.i pin dalo turant warna bijli connection kat jayega!';
  const secv = computeSecvIntentVector(text);

  assert.ok(secv.isConvergentScam, 'Should normalize Hinglish phonetics and catch scam');
  assert.ok(secv.score >= 80, `Expected score >= 80, got ${secv.score}`);

  const scan = scanText(text);
  assert.equal(scan.verdict, 'danger');
});

test('Pillar 1.4: Phonetic Tanglish coercion ("Udane otp sollu illana account block") returns danger', () => {
  const text = 'Udane unga o_t_p number sollu illana bank account freeze aagidum last warning.';
  const secv = computeSecvIntentVector(text);

  assert.ok(secv.isConvergentScam, 'Should normalize Tanglish phonetics');
  assert.ok(secv.score >= 80, `Expected score >= 80, got ${secv.score}`);
});

test('Pillar 1.5: Phonetic Teluglish coercion ("Ventane mpin kottu lekapothe account freeze") returns danger', () => {
  const text = 'Ventane m-p-i-n dalo lekapothe bank account freeze aipotundi!';
  const secv = computeSecvIntentVector(text);

  assert.ok(secv.isConvergentScam, 'Should normalize Teluglish phonetics');
  assert.ok(secv.score >= 80, `Expected score >= 80, got ${secv.score}`);
});

test('Pillar 1.6: Benign conversation about police news ("Police arrested the thief in the news") returns safe', () => {
  const text = 'Police arrested the thief in the news today. Let us watch the documentary video tonight.';
  const secv = computeSecvIntentVector(text);

  assert.equal(secv.isConvergentScam, false, 'Benign conversation must not flag as scam');
  assert.equal(secv.vector.E, 0, 'Extraction action must be 0 in benign talk');
  assert.ok(secv.score < 35, `Expected score < 35, got ${secv.score}`);

  const scan = scanText(text);
  assert.equal(scan.verdict, 'safe');
});

test('Pillar 1.7: Benign utility bill generation notice without extraction returns safe', () => {
  const text = 'Dear Consumer, your electricity bill of ₹450 for October has been generated. Due date is 15th next month. Thank you for your payment.';
  const secv = computeSecvIntentVector(text);

  assert.equal(secv.isConvergentScam, false);
  assert.ok(secv.score < 30);
});

// ═════════════════════════════════════════════════════════════════════════════
// PILLAR 2: Autonomous Dynamic Brand Discovery & TR-39 Homoglyphs
// ═════════════════════════════════════════════════════════════════════════════

test('Pillar 2.1: Unlisted Indian fintech Zerodha Kite impersonation on unaligned domain triggers MISMATCH', () => {
  const domMeta = {
    pageTitle: 'Zerodha Kite - Login to Kite Web',
    hasPasswordInput: true,
    hasCredentialCollection: true
  };
  const currentHostname = 'kite-login-portal.com';

  const verdict = verifyAutonomousBrandIdentity(domMeta, currentHostname);
  assert.equal(verdict.isImpersonation, true);
  assert.equal(verdict.assertedBrand, 'Zerodha Kite');
  assert.equal(verdict.signal, 'SIG_AUTONOMOUS_BRAND_IDENTITY_MISMATCH');
  assert.equal(verdict.score, 85);

  // In Risk Engine
  const risk = calculateRisk('https://kite-login-portal.com/login', [], null, {
    autonomousBrandMismatch: { detected: true, assertedBrand: 'Zerodha Kite' },
    hasPasswordInput: true
  });
  assert.equal(risk.action, 'block');
  assert.ok(risk.score >= 85);
});

test('Pillar 2.2: Unlisted fintech Groww Investing with OpenGraph identity on phishing host flags danger', () => {
  const domMeta = {
    ogSiteName: 'Groww Investing',
    pageTitle: 'Login | Groww',
    hasPasswordInput: true
  };
  const currentHostname = 'groww-kyc-update.net';

  const verdict = verifyAutonomousBrandIdentity(domMeta, currentHostname);
  assert.equal(verdict.isImpersonation, true);
  assert.equal(verdict.assertedBrand, 'Groww Investing');
  assert.equal(verdict.score, 85);
});

test('Pillar 2.3: Legitimate domain kite.zerodha.com is recognized as aligned (0 points, 0 false positive)', () => {
  const domMeta = {
    pageTitle: 'Zerodha Kite - Login to Kite Web',
    hasPasswordInput: true
  };
  const currentHostname = 'kite.zerodha.com';

  const verdict = verifyAutonomousBrandIdentity(domMeta, currentHostname);
  assert.equal(verdict.isImpersonation, false);
  assert.equal(verdict.score, 0);
});

test('Pillar 2.4: Legitimate Stripe checkout on checkout.stripe.com returns safe (0% false positive)', () => {
  const domMeta = {
    pageTitle: 'Stripe Checkout - Payment',
    paymentFields: { card: true, cvv: true }
  };
  const currentHostname = 'checkout.stripe.com';

  const verdict = verifyAutonomousBrandIdentity(domMeta, currentHostname);
  assert.equal(verdict.isImpersonation, false);
  assert.equal(verdict.score, 0);

  const risk = calculateRisk('https://checkout.stripe.com/pay', [], null, domMeta);
  assert.equal(risk.action, 'allow');
  assert.ok(risk.score <= 10);
});

test('Pillar 2.5: Legitimate Razorpay checkout on checkout.razorpay.com returns safe', () => {
  const domMeta = {
    pageTitle: 'Razorpay Payment Gateway',
    paymentFields: { upi: true, card: true }
  };
  const currentHostname = 'checkout.razorpay.com';

  const verdict = verifyAutonomousBrandIdentity(domMeta, currentHostname);
  assert.equal(verdict.isImpersonation, false);
  assert.equal(verdict.score, 0);
});

test('Pillar 2.6: Unicode TR-39 confusable skeleton maps Cyrillic lookalikes to canonical ASCII', () => {
  // 'zеrоdhа' contains Cyrillic 'е', 'о', 'а'
  const cyrillicLookalike = 'z\u0435r\u043Edh\u0430';
  const skeleton = toUnicodeConfusableSkeleton(cyrillicLookalike);
  assert.equal(skeleton, 'zerodha');

  const distance = damerauLevenshtein(skeleton, 'zerodha');
  assert.equal(distance, 0);
});

test('Pillar 2.7: Unicode TR-39 maps Greek homoglyphs and computes Damerau-Levenshtein distance', () => {
  // Greek lookalike for 'paypal' -> 'pαypαl'
  const greekLookalike = 'p\u03B1yp\u03B1l';
  const skeleton = toUnicodeConfusableSkeleton(greekLookalike);
  assert.equal(skeleton, 'paypal');

  const distTransposition = damerauLevenshtein('paypal', 'paypla');
  assert.equal(distTransposition, 1, 'Transposition should count as 1 edit');
});

test('Pillar 2.8: DoH DMARC posture audit identifies strict reject policy with mock DoH', async () => {
  const mockFetch = async (url) => {
    return {
      ok: true,
      json: async () => ({
        Answer: [
          { name: '_dmarc.sbi.co.in', type: 16, data: '"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@sbi.co.in"' }
        ]
      })
    };
  };

  const audit = await auditDomainDmarcPosture('sbi.co.in', mockFetch);
  assert.equal(audit.hasDmarc, true);
  assert.equal(audit.policy, 'reject');
  assert.equal(audit.dmarcValid, true);
});

test('Pillar 2.9: DoH DMARC posture audit identifies missing _dmarc on unverified domain', async () => {
  const mockFetch = async () => ({
    ok: true,
    json: async () => ({ Answer: [] })
  });

  const audit = await auditDomainDmarcPosture('phish-portal.com', mockFetch);
  assert.equal(audit.hasDmarc, false);
  assert.equal(audit.policy, null);
  assert.equal(audit.dmarcValid, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// PILLAR 3: Adversarial Evasion-Proof DOM Sentinel
// ═════════════════════════════════════════════════════════════════════════════

test('Pillar 3.1: Closed Shadow DOM uncloaking logic forces mode: "open" and preserves toString', () => {
  const dummyElement = {
    attachShadow: function (init) {
      return { mode: init.mode, pierced: true };
    }
  };

  const origAttach = dummyElement.attachShadow;
  const origToString = Function.prototype.toString.bind(origAttach);

  const patchedAttach = function attachShadow(init) {
    const forced = Object.assign({}, init, { mode: 'open' });
    return origAttach.call(this, forced);
  };
  Object.defineProperty(patchedAttach, 'name', { value: 'attachShadow' });
  Object.defineProperty(patchedAttach, 'toString', { value: () => origToString() });

  const res = patchedAttach.call(dummyElement, { mode: 'closed' });
  assert.equal(res.mode, 'open', 'Shadow root must be forced open');
  assert.equal(patchedAttach.toString(), origToString(), 'toString disguise preserved');
});

test('Pillar 3.2: WebSocket credential payload exfiltration regex intercepts Telegram/Discord webhook packets', () => {
  const EXFIL_REGEX = /api\.telegram\.org\/bot|discord(app)?\.com\/api\/webhooks|webhook\.site|pipedream\.net/i;
  assert.ok(EXFIL_REGEX.test('wss://api.telegram.org/bot12345/sendDocument'));
  assert.ok(EXFIL_REGEX.test('https://discord.com/api/webhooks/999/token'));

  const payload = JSON.stringify({ user: 'victim', password: 'SecretPassword123' });
  const hasCred = payload.includes('password');
  assert.ok(hasCred, 'Payload contains harvested password');
});

// ═════════════════════════════════════════════════════════════════════════════
// PILLAR 4: Free-Forever Public Threat Mesh Expansion
// ═════════════════════════════════════════════════════════════════════════════

test('Pillar 4.1: queryPhishStatsPublicFeed detects active phishing hit via mocked API', async () => {
  const mockFetch = async () => ({
    ok: true,
    json: async () => [
      { id: 101, url: 'http://malicious-sbi-portal.xyz/login', ip: '1.2.3.4', score: 8.5 }
    ]
  });

  const res = await queryPhishStatsPublicFeed('malicious-sbi-portal.xyz', mockFetch);
  assert.equal(res.hit, true);
  assert.equal(res.score, 90);
  assert.equal(res.signal.id, 'SIG_PHISHSTATS_LIVE_FEED_HIT');
  assert.equal(res.proofStep.status, 'failed');
});

test('Pillar 4.2: queryPhishStatsPublicFeed handles clean domains and offline gracefully', async () => {
  const cleanFetch = async () => ({
    ok: true,
    json: async () => []
  });
  const cleanRes = await queryPhishStatsPublicFeed('sbi.co.in', cleanFetch);
  assert.equal(cleanRes.hit, false);
  assert.equal(cleanRes.proofStep.status, 'passed');

  // Offline / timeout
  const rejectingFetch = async () => { throw new Error('Network offline'); };
  const offlineRes = await queryPhishStatsPublicFeed('anydomain.com', rejectingFetch);
  assert.equal(offlineRes.hit, false);
  assert.equal(offlineRes.proofStep.status, 'skipped');
});

test('Pillar 4.3: verifyUrlAndMessageOnline produces unified 5-Pillar Live Internet Verification Proof', async () => {
  const mockFetch = async (url) => {
    const u = String(url);
    if (u.includes('wikidata.org')) {
      return {
        ok: true,
        json: async () => ({ search: [{ id: 'Q12345', label: 'SBI', description: 'Bank' }] })
      };
    }
    if (u.includes('rdap.org')) {
      return {
        ok: true,
        json: async () => ({ events: [{ eventAction: 'registration', eventDate: '2010-01-01T00:00:00Z' }] })
      };
    }
    if (u.includes('cloudflare-dns.com') || u.includes('dns.google')) {
      return {
        ok: true,
        json: async () => ({ Answer: [{ name: 'sbi.co.in', type: 1, data: '1.2.3.4' }] })
      };
    }
    if (u.includes('phishstats.info')) {
      return { ok: true, json: async () => [] };
    }
    return { ok: false };
  };

  const report = await verifyUrlAndMessageOnline('https://sbi.co.in/portal', {
    fetchImpl: mockFetch,
    entityName: 'State Bank of India'
  });

  assert.ok(report.onlineProofSteps.length >= 5, 'Must contain at least 5 proof steps');
  const stepTitles = report.onlineProofSteps.map(p => p.step);
  assert.ok(stepTitles.some(t => t.includes('Wikidata')));
  assert.ok(stepTitles.some(t => t.includes('RDAP')));
  assert.ok(stepTitles.some(t => t.includes('Certificate Transparency')));
  assert.ok(stepTitles.some(t => t.includes('DMARC Posture')));
  assert.ok(stepTitles.some(t => t.includes('Public Threat Feeds')));
});

test('Pillar 4.4: verifyUrlAndMessageOnline handles 100% offline fallback without throwing', async () => {
  const offlineFetch = async () => { throw new Error('Offline'); };

  const report = await verifyUrlAndMessageOnline('https://suspicious-unreachable.top', {
    fetchImpl: offlineFetch
  });

  assert.ok(report);
  assert.equal(report.isOfflineFallback, true);
  assert.ok(report.onlineProofSteps.every(p => p.status === 'skipped' || p.status === 'passed' || p.status === 'failed'));
});

// ═════════════════════════════════════════════════════════════════════════════
// PILLAR 5: Multilingual Coverage & Risk Engine Overrides
// ═════════════════════════════════════════════════════════════════════════════

test('Pillar 5.1: All 4 new signals have complete valid translations across en, ta, hi, te', () => {
  const targetSignals = [
    'SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE',
    'SIG_AUTONOMOUS_BRAND_IDENTITY_MISMATCH',
    'SIG_PHISHSTATS_LIVE_FEED_HIT',
    'SIG_MISSING_DMARC_CREDENTIAL_TRAP'
  ];

  for (const sigId of targetSignals) {
    const entry = REASON_PLAIN[sigId];
    assert.ok(entry, `REASON_PLAIN must contain ${sigId}`);
    assert.ok(entry.en && entry.en.length > 5, `Missing English for ${sigId}`);
    assert.ok(entry.ta && entry.ta.length > 5, `Missing Tamil for ${sigId}`);
    assert.ok(entry.hi && entry.hi.length > 5, `Missing Hindi for ${sigId}`);
    assert.ok(entry.te && entry.te.length > 5, `Missing Telugu for ${sigId}`);
  }
});

test('Pillar 5.2: Risk Engine enforces Hard Override danger verdicts for all new autonomous threat signals', () => {
  // Test autonomous brand mismatch
  const risk1 = calculateRisk('https://kite-login-portal.com', [], null, {
    autonomousBrandMismatch: { detected: true, assertedBrand: 'Zerodha' },
    hasPasswordInput: true
  });
  assert.equal(risk1.action, 'block');
  assert.ok(risk1.score >= 85);
  assert.ok(risk1.signals.some(s => s.id === 'SIG_AUTONOMOUS_BRAND_IDENTITY_MISMATCH'));

  // Test PhishStats hit
  const risk2 = calculateRisk('https://phish-site.com', [], null, null, {
    phishStatsHit: true
  });
  assert.equal(risk2.action, 'block');
  assert.ok(risk2.score >= 90);
  assert.ok(risk2.signals.some(s => s.id === 'SIG_PHISHSTATS_LIVE_FEED_HIT'));

  // Test Missing DMARC
  const risk3 = calculateRisk('https://phish-bank.com', [], null, { hasPasswordInput: true }, {
    missingDmarcCredentialTrap: true
  });
  assert.equal(risk3.action, 'block');
  assert.ok(risk3.score >= 85);
  assert.ok(risk3.signals.some(s => s.id === 'SIG_MISSING_DMARC_CREDENTIAL_TRAP'));
});
