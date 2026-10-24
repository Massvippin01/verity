/**
 * tests/hybrid_ai_and_online_intel.test.js
 *
 * Comprehensive Test Suite for:
 * 1. Subword Character N-Gram + Word Bayesian Softmax NLP (ai-nlp-classifier.js & text-scanner.js)
 * 2. Online Free-Forever CT Log & DNS CNAME/IP Forensics (online-free-intel.js)
 * 3. Continuous 8D DOM Vector Embedding & 2-Layer Neural MLP Meta-Fusion (ai-meta-fusion.js)
 * 4. Risk Engine End-to-End Synergy & Invariant Verification
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { classifyTextWithSubwordAi } from '../shared/ai-nlp-classifier.js';
import { scanTextForScams } from '../shared/text-scanner.js';
import { evaluateCtLogForensics, evaluateDohPacketForensics } from '../background/online-free-intel.js';
import { computeDomTopologyVector, runNeuralMetaFusion } from '../background/ai-meta-fusion.js';
import { calculateRisk } from '../background/risk-engine.js';
import { REASON_PLAIN, goldenRuleForSignal, GOLDEN_RULES } from '../shared/citizen-messages.js';

// ── 1. Subword Character N-Gram + Word Bayesian NLP Tests ───────────────────

test('Subword AI 1: Obfuscated electricity power disconnection scam is caught with scamProbability >= 0.80', () => {
  const text = 'Ur elctrcity pwr wl b discnnected 2nite pay immdtly to helpline';
  const result = classifyTextWithSubwordAi(text);
  assert.equal(result.isScam, true);
  assert.ok(result.scamProbability >= 0.80, `Expected prob >= 0.80, got ${result.scamProbability}`);
  assert.ok(result.score >= 80, `Expected score >= 80, got ${result.score}`);
  assert.equal(result.signal, 'SIG_AI_NLP_SCAM_INTENT');
});

test('Subword AI 2: Mutated UPI PIN refund lure is caught with scamProbability >= 0.80', () => {
  const text = 'Entr ur 6 dgt u_p_i p1n 2 clm rfund of 25000 rs immdtly';
  const result = classifyTextWithSubwordAi(text);
  assert.equal(result.isScam, true);
  assert.ok(result.scamProbability >= 0.80, `Expected prob >= 0.80, got ${result.scamProbability}`);
  assert.equal(result.dominantClass, 'CREDENTIAL_PAYMENT_EXTRACTION');
});

test('Subword AI 3: Obfuscated CBI police digital arrest threat is caught with scamProbability >= 0.80', () => {
  const text = 'CBI pol1ce dgtal arrst ordr issud agnst ur aadhaar attend video conf immdtly';
  const result = classifyTextWithSubwordAi(text);
  assert.equal(result.isScam, true);
  assert.ok(result.scamProbability >= 0.80, `Expected prob >= 0.80, got ${result.scamProbability}`);
  assert.ok(result.dominantClass === 'COERCION_EXTORTION' || result.dominantClass === 'URGENCY_SOCIAL_ENGINEERING');
});

test('Subword AI 4: Mutated APK dropper delivery lure is caught with scamProbability >= 0.80', () => {
  const text = 'Dwnld this updt .apk file to complt ur kyc or sim block';
  const result = classifyTextWithSubwordAi(text);
  assert.equal(result.isScam, true);
  assert.ok(result.scamProbability >= 0.80, `Expected prob >= 0.80, got ${result.scamProbability}`);
  assert.equal(result.dominantClass, 'MALWARE_DROPPER_DELIVERY');
});

test('Subword AI 5: Benign conversational message 1 scores scamProbability < 0.20 (0% False Positive)', () => {
  const text = "Hey let's meet for dinner at 8pm after work";
  const result = classifyTextWithSubwordAi(text);
  assert.equal(result.isScam, false);
  assert.ok(result.scamProbability < 0.20, `Expected prob < 0.20, got ${result.scamProbability}`);
  assert.equal(result.score, 0);
});

test('Subword AI 6: Benign conversational message 2 scores scamProbability < 0.20 (0% False Positive)', () => {
  const text = 'Can you send me the project PDF notes? We can discuss in tomorrow morning meeting.';
  const result = classifyTextWithSubwordAi(text);
  assert.equal(result.isScam, false);
  assert.ok(result.scamProbability < 0.20, `Expected prob < 0.20, got ${result.scamProbability}`);
  assert.equal(result.score, 0);
});

test('Subword AI 7: scanTextForScams integration returns danger on obfuscated scam text', () => {
  const text = 'Ur elctrcity pwr wl b discnnected 2nite pay immdtly';
  const verdict = scanTextForScams(text);
  assert.equal(verdict.verdict, 'danger');
  assert.ok(verdict.score >= 80, `Expected score >= 80, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_AI_NLP_SCAM_INTENT'));
});

// ── 2. Online Free-Forever CT Log & DNS Forensics Tests ─────────────────────

test('CT Log Forensics 1: 2-day-old Let\'s Encrypt cert requesting credentials triggers SIG_CT_LOG_EPHEMERAL_CERT_PHISH', () => {
  const now = new Date();
  const twoDaysAgo = new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000).toISOString();
  const sampleCtEntries = [
    {
      issuer_name: "C=US, O=Let's Encrypt, CN=R3",
      not_before: twoDaysAgo,
      entry_timestamp: twoDaysAgo
    }
  ];

  const result = evaluateCtLogForensics(sampleCtEntries, 'portal-secure-update.com', true);
  assert.equal(result.isEphemeral, true);
  assert.equal(result.signal, 'SIG_CT_LOG_EPHEMERAL_CERT_PHISH');
  assert.equal(result.score, 88);
  assert.equal(result.hardOverride, true);
  assert.ok(result.earliestCertAgeDays <= 3);
});

test('CT Log Forensics 2: Established domain with 400-day-old cert history adds 0 risk points', () => {
  const now = new Date();
  const fourHundredDaysAgo = new Date(now.getTime() - 400 * 24 * 60 * 60 * 1000).toISOString();
  const sampleCtEntries = [
    {
      issuer_name: "C=US, O=DigiCert Inc, CN=DigiCert Global Root CA",
      not_before: fourHundredDaysAgo,
      entry_timestamp: fourHundredDaysAgo
    }
  ];

  const result = evaluateCtLogForensics(sampleCtEntries, 'legitimate-corp.com', true);
  assert.equal(result.isEphemeral, false);
  assert.equal(result.signal, null);
  assert.equal(result.score, 0);
  assert.ok(result.earliestCertAgeDays >= 390);
});

test('DNS Forensics 1: CNAME pointing to trycloudflare.com tunnel triggers SIG_DNS_CNAME_CLOAKING_DETECTED', () => {
  const dohResponse = {
    Status: 0,
    Answer: [
      { name: 'login-update.com', type: 5, data: 'phish-kit-99.trycloudflare.com.' },
      { name: 'phish-kit-99.trycloudflare.com.', type: 1, data: '104.16.1.1' }
    ]
  };

  const result = evaluateDohPacketForensics(dohResponse, 'login-update.com');
  assert.equal(result.hasCnameCloak, true);
  assert.equal(result.signal, 'SIG_DNS_CNAME_CLOAKING_DETECTED');
  assert.equal(result.score, 80);
  assert.ok((result.cnameTarget || '').includes('trycloudflare.com'));
});

test('DNS Forensics 2: CNAME pointing to serverless .pages.dev or .vercel.app triggers cloaking signal', () => {
  const dohResponse = {
    Status: 0,
    Answer: [
      { name: 'sbi-kyc-verify.com', type: 5, data: 'sbi-trap.pages.dev.' },
      { name: 'sbi-trap.pages.dev.', type: 1, data: '172.67.1.1' }
    ]
  };

  const result = evaluateDohPacketForensics(dohResponse, 'sbi-kyc-verify.com');
  assert.equal(result.hasCnameCloak, true);
  assert.equal(result.signal, 'SIG_DNS_CNAME_CLOAKING_DETECTED');
  assert.equal(result.score, 80);
});

test('DNS Forensics 3: Sinkhole IP (0.0.0.0 or 127.0.0.1) triggers sinkhole blocking signal', () => {
  const dohResponse = {
    Status: 0,
    Answer: [
      { name: 'known-malware-c2.net', type: 1, data: '0.0.0.0' }
    ]
  };

  const result = evaluateDohPacketForensics(dohResponse, 'known-malware-c2.net');
  assert.equal(result.isSinkholed, true);
  assert.equal(result.signal, 'SIG_DOH_MALWARE_SINKHOLE_DETECTED');
  assert.equal(result.score, 95);
});

test('DNS Forensics 4: Direct standard A-record returns safe without CNAME cloak', () => {
  const dohResponse = {
    Status: 0,
    Answer: [
      { name: 'company.com', type: 1, data: '93.184.216.34' }
    ]
  };

  const result = evaluateDohPacketForensics(dohResponse, 'company.com');
  assert.equal(result.hasCnameCloak, false);
  assert.equal(result.isSinkholed, false);
  assert.equal(result.signal, null);
  assert.equal(result.score, 0);
});

// ── 3. Continuous 8D DOM Vector & 2-Layer Neural MLP Tests ───────────────────

test('Continuous DOM Vector: computeDomTopologyVector projects metrics into continuous vector space', () => {
  const metrics = {
    deadLinkRatio: 0.48,
    externalLinkRatio: 0.30,
    externalMediaRatio: 0.42,
    hasPasswordInput: true,
    isFormOrphaned: true
  };

  const result = computeDomTopologyVector(metrics);
  assert.equal(result.vector.length, 6);
  assert.ok(result.phishSim > 0.60, `Expected phishSim > 0.60, got ${result.phishSim}`);
  assert.ok(result.domCosinePhishSim > 0.40, `Expected domCosinePhishSim > 0.40, got ${result.domCosinePhishSim}`);
});

test('Neural Meta-Fusion 1: Sub-threshold stealth phishing page fires P_threat >= 0.85', () => {
  // Every single rule deliberately stays below its hardcoded trigger:
  // - deadLinkRatio: 0.48 (below 0.60 hard cutoff)
  // - externalMediaRatio: 0.42 (below 0.50 hard cutoff)
  // - domainAgeDays: 16 (above 14 day NRD hard cutoff)
  // - markovScore: 48 (below 55 hard cutoff)
  // Plus credential inputs
  const domTopology = computeDomTopologyVector({
    deadLinkRatio: 0.48,
    externalMediaRatio: 0.42,
    hasPasswordInput: true
  });

  const featureVector = {
    urlOnnxProb: 0.0,
    markovAnomalyProb: 0.48,
    shannonEntropyNorm: 0.40,
    domCosinePhishSim: domTopology.domCosinePhishSim,
    hasCredentialInputs: 1.0,
    nlpScamProb: 0.0,
    domainNewnessDecay: Math.exp(-16 / 14), // ~0.3188
    cnameOrFreeHostCloak: 0.0,
    redirectVelocityNorm: 0.0,
    brandProximityNorm: 0.0
  };

  const result = runNeuralMetaFusion(featureVector);
  assert.ok(result.threatProbability >= 0.85, `Expected P_threat >= 0.85, got ${result.threatProbability}`);
  assert.equal(result.isPhish, true);
  assert.ok(result.score >= 85, `Expected score >= 85, got ${result.score}`);
  assert.equal(result.signal, 'SIG_NEURAL_META_FUSION_PHISH');
});

test('Neural Meta-Fusion 2: Legitimate enterprise portal scores P_threat < 0.15 (SAFE)', () => {
  const domTopology = computeDomTopologyVector({
    deadLinkRatio: 0.02,
    externalLinkRatio: 0.05,
    externalMediaRatio: 0.02,
    hasPasswordInput: true
  });

  const featureVector = {
    urlOnnxProb: 0.0,
    markovAnomalyProb: 0.0,
    shannonEntropyNorm: 0.1,
    domCosinePhishSim: domTopology.domCosinePhishSim,
    hasCredentialInputs: 1.0,
    nlpScamProb: 0.0,
    domainNewnessDecay: 0.0, // Mature domain (> 60 days)
    cnameOrFreeHostCloak: 0.0,
    redirectVelocityNorm: 0.0,
    brandProximityNorm: 0.0
  };

  const result = runNeuralMetaFusion(featureVector);
  assert.ok(result.threatProbability < 0.15, `Expected P_threat < 0.15, got ${result.threatProbability}`);
  assert.equal(result.isPhish, false);
  assert.equal(result.signal, null);
});

// ── 4. End-to-End Risk Engine Integration Tests ──────────────────────────────

test('Risk Engine Integration 1: Ephemeral CT Log cert triggers Block verdict with Score 88', () => {
  const url = 'https://urgent-account-verify.org/login';
  const threatIntel = {
    ctRisk: {
      signal: 'SIG_CT_LOG_EPHEMERAL_CERT_PHISH',
      earliestCertAgeDays: 2,
      reason: 'First TLS certificate issued 2 days ago'
    }
  };
  const domSignals = { hasPasswordInput: true };

  const verdict = calculateRisk(url, [], null, domSignals, threatIntel);
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 88, `Expected score >= 88, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_CT_LOG_EPHEMERAL_CERT_PHISH'));
});

test('Risk Engine Integration 2: DNS CNAME cloaking triggers Block verdict with Score 80', () => {
  const url = 'https://login-portal-sync.com/auth';
  const threatIntel = {
    dohRisk: {
      signal: 'SIG_DNS_CNAME_CLOAKING_DETECTED',
      cname: 'stealth-kit.trycloudflare.com',
      reason: 'CNAME points to free tunnel endpoint'
    }
  };
  const domSignals = { hasPasswordInput: true };

  const verdict = calculateRisk(url, [], null, domSignals, threatIntel);
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 80, `Expected score >= 80, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_DNS_CNAME_CLOAKING_DETECTED'));
});

test('Risk Engine Integration 3: Sub-threshold stealth phishing features trigger Neural MLP block', () => {
  const url = 'https://stealth-subthreshold-login.net/account';
  const domSignals = {
    deadLinkRatio: 0.48,
    externalMediaRatio: 0.42,
    hasPasswordInput: true,
    hasCredentialCollection: true,
    markovScore: 48,
    domainAgeDays: 16
  };

  const verdict = calculateRisk(url, [], null, domSignals, null);
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85, `Expected score >= 85, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'SIG_NEURAL_META_FUSION_PHISH'));
});

test('Risk Engine Integration 4: Clean SaaS login page remains Safe with score <= 35', () => {
  const url = 'https://app.custom-crm-portal.com/login';
  const domSignals = {
    deadLinkRatio: 0.02,
    externalMediaRatio: 0.02,
    hasPasswordInput: true,
    hasCredentialCollection: true,
    domainAgeDays: 450
  };

  const verdict = calculateRisk(url, [], null, domSignals, null);
  assert.notEqual(verdict.action, 'block');
  assert.ok(verdict.score <= 35, `Expected score <= 35, got ${verdict.score}`);
  assert.ok(!verdict.signals.some(s => s.id === 'SIG_NEURAL_META_FUSION_PHISH'));
});

test('Citizen Messages: All 4 new signals have complete, valid translations in en, ta, hi, te', () => {
  const signals = [
    'SIG_CT_LOG_EPHEMERAL_CERT_PHISH',
    'SIG_DNS_CNAME_CLOAKING_DETECTED',
    'SIG_NEURAL_META_FUSION_PHISH',
    'SIG_AI_NLP_SCAM_INTENT'
  ];

  const langs = ['en', 'ta', 'hi', 'te'];

  for (const sig of signals) {
    for (const lang of langs) {
      const msg = REASON_PLAIN[sig]?.[lang];
      assert.ok(msg && msg.length > 5, `Expected valid message for ${sig} in ${lang}`);

      const ruleKey = goldenRuleForSignal(sig);
      assert.ok(ruleKey, `Expected golden rule key for ${sig}`);
      const ruleText = GOLDEN_RULES[ruleKey]?.[lang];
      assert.ok(ruleText && ruleText.length > 5, `Expected golden rule text for ${sig} in ${lang}`);
    }
  }
});
