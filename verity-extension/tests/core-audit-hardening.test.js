/**
 * tests/core-audit-hardening.test.js — Core Engine Security Hardening & Audit Verification
 *
 * Verifies fixes for all 23 audit vulnerabilities across Phases 1–4:
 * 1.  C1: Maximum Severity Floor Resolver (Order-Invariant, non-masking)
 * 2.  C2 & C3: Category Mapping & Object.seal Guard
 * 3.  C4: FIPS 180-4 Pure-JS SHA-256 Digest Precision
 * 4.  C5: Allowlist Runtime Compromise Invariant Guard
 * 5.  H7: URL and Hostname Verdict Parity
 * 6.  H1 & L4: Modular Engine Constants & Score Floors
 * 7.  H4: 10-Element Diminishing Returns Category Scaling
 * 8.  H6: CSPRNG ScanId Predictability Defeat
 * 9.  H2: Neural Meta-Fusion 18-Feature Calibration Metadata
 * 10. H3: Leetspeak & Stemmed Token NLP Resilience
 * 11. M1: Mixed-Script Homoglyph & Punycode DGA Detection
 * 12. M2: SECV Multi-Axis Coercion Synergy (E = 0)
 * 13. M4: Evidence Vault Ring Buffer & Quota Resilience
 * 14. M5: Signal Parameter HTML Sanitization
 * 15. Performance: < 5ms calculateRisk Execution Benchmark
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { calculateRisk, sanitizeSignalParams } from '../background/risk-engine.js';
import {
  THRESHOLDS,
  DIMINISHING_WEIGHTS,
  SCORE_FLOORS,
  applyScoreFloors
} from '../shared/engine-constants.js';
import { generateScanId } from '../shared/verdict-contract.js';
import { MODEL_CALIBRATION_METADATA } from '../background/ai-meta-fusion.js';
import {
  classifyTextWithSubwordAi,
  normalizeLeetspeakChars,
  stemToken
} from '../shared/ai-nlp-classifier.js';
import { computeLexicalAnomalyScore } from '../shared/markov-lexical-scorer.js';
import { computeSecvIntentVector } from '../shared/secv-intent-engine.js';
import {
  pureJsSha256,
  computeSha256,
  MAX_VAULT_RECORDS,
  getVaultAnchorHash,
  setVaultAnchorHash,
  saveRecordToVault,
  getVaultRecords,
  verifyVaultChainIntegrity
} from '../../mobile-scanner/scanner.js';

// Setup Mock LocalStorage for Mobile Vault tests in Node.js
if (typeof globalThis.localStorage === 'undefined') {
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => store.get(k) || null,
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
    clear: () => store.clear()
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. C1: MAXIMUM SEVERITY FLOOR RESOLVER (ORDER-INVARIANT, NON-MASKING)
// ═════════════════════════════════════════════════════════════════════════════

test('C1.1: Multi-vector threat with AI NLP Scam Intent (floor 82) + BitB Attack (floor 95) resolves to >= 95', () => {
  const domSignals = {
    aiNlpScamIntent: { scamProbability: 0.95 },
    bitbAttack: { detected: true, iframeUrl: 'https://accounts.google.com/o/oauth2/auth' }
  };
  const verdict = calculateRisk('https://phish-hub.xyz/login', [], null, domSignals);
  assert.ok(verdict.score >= 95, `Expected score >= 95, got ${verdict.score}`);
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
});

test('C1.2: Multi-vector threat with SECV Convergence (floor 85) + Clipboard Address Swap (floor 95) resolves to >= 95', () => {
  const domSignals = {
    secvIntent: { isConvergentScam: true },
    clipboardAddressSwap: { detected: true, swappedType: 'ETH' }
  };
  const verdict = calculateRisk('https://claim-airdrop.xyz/connect', [], null, domSignals);
  assert.ok(verdict.score >= 95, `Expected score >= 95, got ${verdict.score}`);
  assert.equal(verdict.action, 'block');
});

test('C1.3: Multi-vector threat with Free Hosting Phish (floor 75) + Phishing Kit Webhook Exfil (floor 95) resolves to >= 95', () => {
  const domSignals = {
    hasPasswordInput: true,
    hasPhishingKitWebhookExfil: true,
    webhookAction: true
  };
  const verdict = calculateRisk('https://sbi-login.workers.dev/login', [], null, domSignals);
  assert.ok(verdict.score >= 95, `Expected score >= 95, got ${verdict.score}`);
  assert.equal(verdict.action, 'block');
});

test('C1.4: Overlapping multi-threat floors resolve independently to highest floor without branch skipping', () => {
  const score = applyScoreFloors(50, {
    hasAiNlpScamIntent: true,
    hasAutonomousBrandMismatch: true,
    hasKeyloggerHoneytokenTripped: true,
    hasAitmReverseProxy: true
  });
  assert.equal(score, 95);
});

// ═════════════════════════════════════════════════════════════════════════════
// 2. C2 & C3: CATEGORY MAPPING & OBJECT.SEAL GUARDS
// ═════════════════════════════════════════════════════════════════════════════

test('C2.1: Surveillance Extortion Trap properly maps to categories.scamFraud.flagged === true', () => {
  const domSignals = {
    surveillanceExtortionTrap: { detected: true, matchedLure: 'digital arrest warrant' }
  };
  const verdict = calculateRisk('https://police-cyber-notice.com/case', [], null, domSignals);
  assert.equal(verdict.categories.scamFraud.flagged, true);
  assert.ok(verdict.categories.scamFraud.reason.includes('digital arrest warrant'));
});

test('C3.1: NPCI Unsigned Collect Forensic Trap properly maps to categories.scamFraud.flagged === true', () => {
  const domSignals = {
    npciUnsignedCollect: { detected: true, payeeVpa: 'fraudster@ybl' }
  };
  const verdict = calculateRisk('https://utility-bill-discount.top/pay', [], null, domSignals);
  assert.equal(verdict.categories.scamFraud.flagged, true);
  assert.ok(verdict.categories.scamFraud.reason.includes('fraudster@ybl'));
});

test('C2/C3.2: verdict.categories and sub-objects are strictly sealed against phantom property writes', () => {
  const verdict = calculateRisk('https://example.com');
  assert.ok(Object.isSealed(verdict.categories), 'categories must be sealed');
  assert.ok(Object.isSealed(verdict.categories.phishing), 'phishing category must be sealed');
  assert.ok(Object.isSealed(verdict.categories.malware), 'malware category must be sealed');
  assert.ok(Object.isSealed(verdict.categories.scamFraud), 'scamFraud category must be sealed');
  assert.ok(Object.isSealed(verdict.categories.suspicious), 'suspicious category must be sealed');

  // Attempting to write phantom property throws in strict mode
  assert.throws(() => {
    'use strict';
    verdict.categories.scam = { flagged: true };
  }, TypeError);

  assert.throws(() => {
    'use strict';
    verdict.categories.payment = { flagged: true };
  }, TypeError);
});

// ═════════════════════════════════════════════════════════════════════════════
// 3. C4: FIPS 180-4 PURE-JS SHA-256 DIGEST PRECISION
// ═════════════════════════════════════════════════════════════════════════════

test('C4.1: pureJsSha256 produces exact NIST standard digest for "abc"', () => {
  const digest = pureJsSha256('abc');
  assert.equal(digest, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('C4.2: pureJsSha256 produces exact NIST standard digest for empty string ""', () => {
  const digest = pureJsSha256('');
  assert.equal(digest, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('C4.3: computeSha256 produces 64-hex character digest with full 256-bit entropy', async () => {
  const digest = await computeSha256('Verity Mobile Forensics Evidence Seal');
  assert.equal(digest.length, 64);
  assert.ok(/^[0-9a-f]{64}$/.test(digest));
  assert.ok(!digest.endsWith('0000000000000000'), 'Digest must not contain dummy zero padding');
});

// ═════════════════════════════════════════════════════════════════════════════
// 4. C5: ALLOWLIST "UNBREAKABLE INVARIANT" RUNTIME COMPROMISE BYPASS
// ═════════════════════════════════════════════════════════════════════════════

test('C5.1: Compromised allowlisted domain (google.com) exhibiting BitB attack is BLOCKED (score >= 95)', () => {
  const domSignals = {
    bitbAttack: { detected: true, iframeUrl: 'https://accounts.google.com/o/oauth2/auth' },
    hasBitbAttack: true
  };
  const verdict = calculateRisk('https://google.com/search?q=test', [], null, domSignals);
  assert.ok(verdict.score >= 95, `Expected score >= 95 on compromised allowlist, got ${verdict.score}`);
  assert.equal(verdict.action, 'block');
  assert.equal(verdict.severity, 'danger');
});

test('C5.2: Compromised allowlisted domain exhibiting ClickFix attack is BLOCKED', () => {
  const domSignals = {
    clickFix: { detected: true },
    hasClickfixClipboardAttack: true
  };
  const verdict = calculateRisk('https://microsoft.com/en-us', [], null, domSignals);
  assert.ok(verdict.score >= 85, `Expected score >= 85 on compromised allowlist, got ${verdict.score}`);
  assert.equal(verdict.action, 'block');
});

test('C5.3: Compromised allowlisted domain exhibiting Phishing Kit Webhook Exfil is BLOCKED', () => {
  const domSignals = {
    hasPhishingKitWebhookExfil: true,
    webhookAction: true
  };
  const verdict = calculateRisk('https://github.com/login', [], null, domSignals);
  assert.ok(verdict.score >= 95, `Expected score >= 95, got ${verdict.score}`);
  assert.equal(verdict.action, 'block');
});

test('C5.4: Compromised allowlisted domain exhibiting Clipboard Address Swap is BLOCKED', () => {
  const domSignals = {
    clipboardAddressSwap: { detected: true },
    hasClipboardAddressSwap: true
  };
  const verdict = calculateRisk('https://amazon.com/gp/buy', [], null, domSignals);
  assert.ok(verdict.score >= 95, `Expected score >= 95, got ${verdict.score}`);
  assert.equal(verdict.action, 'block');
});

test('C5.5: Compromised allowlisted domain with UPI Collect Trap is BLOCKED', () => {
  const domSignals = {
    upiQrCollectTrap: { detected: true },
    hasUpiCollectTrap: true
  };
  const verdict = calculateRisk('https://apple.com/shop', [], null, domSignals);
  assert.ok(verdict.score >= 85);
  assert.equal(verdict.action, 'block');
});

test('C5.6: Compromised allowlisted domain with Surveillance Extortion Trap is BLOCKED', () => {
  const domSignals = {
    surveillanceExtortionTrap: { detected: true, matchedLure: 'webcam recording' },
    hasSurveillanceExtortionTrap: true
  };
  const verdict = calculateRisk('https://cloudflare.com/network', [], null, domSignals);
  assert.ok(verdict.score >= 90);
  assert.equal(verdict.action, 'block');
});

test('C5.7: Compromised allowlisted domain with Cross-Origin Password Reuse is BLOCKED', () => {
  const domSignals = {
    crossOriginPasswordReuse: { detected: true },
    hasCrossOriginPasswordReuse: true
  };
  const verdict = calculateRisk('https://wikipedia.org/wiki/Main_Page', [], null, domSignals);
  assert.ok(verdict.score >= 95);
  assert.equal(verdict.action, 'block');
});

test('C5.8: Uncompromised allowlisted domain safely returns score 0, allow, safe', () => {
  const verdict = calculateRisk('https://google.com/search');
  assert.equal(verdict.score, 0);
  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.severity, 'safe');
});

// ═════════════════════════════════════════════════════════════════════════════
// 5. H7: URL AND HOSTNAME VERDICT RETURN PARITY
// ═════════════════════════════════════════════════════════════════════════════

test('H7.1: calculateRisk final verdict return object includes url and hostname', () => {
  const url = 'https://unverified-sample-threat.xyz/login';
  const verdict = calculateRisk(url, [{ id: 'RULE_MISSING_HTTPS', score: 10 }]);
  assert.equal(verdict.url, url);
  assert.equal(verdict.hostname, 'unverified-sample-threat.xyz');
});

test('H7.2: calculateRisk early-return trusted domain includes url and hostname', () => {
  const url = 'https://accounts.google.com/o/oauth2/auth';
  const verdict = calculateRisk(url);
  assert.equal(verdict.url, url);
  assert.equal(verdict.hostname, 'accounts.google.com');
  assert.equal(verdict.score, 0);
});

// ═════════════════════════════════════════════════════════════════════════════
// 6. H1 & L4: MODULAR CONSTANTS & SCORE FLOORS
// ═════════════════════════════════════════════════════════════════════════════

test('H1.1: THRESHOLDS, DIMINISHING_WEIGHTS, and SCORE_FLOORS are frozen', () => {
  assert.ok(Object.isFrozen(THRESHOLDS));
  assert.ok(Object.isFrozen(DIMINISHING_WEIGHTS));
  assert.ok(Object.isFrozen(SCORE_FLOORS));
  assert.equal(THRESHOLDS.BLOCK, 70);
  assert.equal(THRESHOLDS.CAUTION, 35);
});

test('H4.1: Extended 10-element diminishing weights array smoothly scales multi-category threats', () => {
  assert.equal(DIMINISHING_WEIGHTS.length, 10);
  assert.equal(DIMINISHING_WEIGHTS[0], 1.0);
  assert.equal(DIMINISHING_WEIGHTS[9], 0.06);
});

// ═════════════════════════════════════════════════════════════════════════════
// 7. H6: CSPRNG SCANID PREDICTABILITY DEFEAT
// ═════════════════════════════════════════════════════════════════════════════

test('H6.1: generateScanId() produces formatted ID matching scn_<ts>_<random>', () => {
  const scanId = generateScanId();
  assert.ok(/^scn_[0-9a-z]+_[0-9a-f]{16}$/.test(scanId), `Invalid scanId format: ${scanId}`);
});

test('H6.2: 100 consecutive generateScanId() calls produce 100 distinct collision-free IDs', () => {
  const set = new Set();
  for (let i = 0; i < 100; i++) {
    set.add(generateScanId());
  }
  assert.equal(set.size, 100, 'All generated scanIds must be unique');
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. H2: NEURAL META-FUSION 18-FEATURE CALIBRATION METADATA
// ═════════════════════════════════════════════════════════════════════════════

test('H2.1: MODEL_CALIBRATION_METADATA exports complete 18-feature architecture baseline', () => {
  assert.equal(MODEL_CALIBRATION_METADATA.modelName, 'Verity-NeuralMetaFusion-MLP');
  assert.equal(MODEL_CALIBRATION_METADATA.inputFeaturesCount, 18);
  assert.equal(MODEL_CALIBRATION_METADATA.architecture, '18 -> 12 -> 1');
  assert.equal(MODEL_CALIBRATION_METADATA.activeRuntimeFeatures.length, 10);
  assert.equal(MODEL_CALIBRATION_METADATA.extendedPillarFeatures.length, 8);
});

test('H2.2: MODEL_CALIBRATION_METADATA baseline contains calibrated centroids', () => {
  assert.ok(MODEL_CALIBRATION_METADATA.calibrationBaseline.decisionThresholdThreat >= 0.80);
  assert.ok(MODEL_CALIBRATION_METADATA.calibrationBaseline.decisionThresholdHardOverride >= 0.85);
});

// ═════════════════════════════════════════════════════════════════════════════
// 9. H3: LEETSPEAK & STEMMED TOKEN NLP RESILIENCE
// ═════════════════════════════════════════════════════════════════════════════

test('H3.1: normalizeLeetspeakChars replaces @, 0, 1, $, 3, 4, 5 substitutions', () => {
  const normalized = normalizeLeetspeakChars('p@ssw0rd_1_cl@im_$bi');
  assert.ok(normalized.includes('password'));
  assert.ok(normalized.includes('claim'));
  assert.ok(normalized.includes('sbi'));
});

test('H3.2: stemToken normalizes common suffix inflections', () => {
  assert.equal(stemToken('arresting'), 'arrest');
  assert.equal(stemToken('warrants'), 'warrant');
  assert.equal(stemToken('blocked'), 'block');
  assert.equal(stemToken('customs'), 'custom');
});

test('H3.3: classifyTextWithSubwordAi catches leetspeak-obfuscated credential extraction', () => {
  const result = classifyTextWithSubwordAi('Plz entr ur p@ssw0rd and cl@im ur rfund 2nite');
  assert.equal(result.isScam, true);
  assert.ok(result.scamProbability >= 0.75);
});

test('H3.4: classifyTextWithSubwordAi catches Hinglish / leetspeak threat message', () => {
  const result = classifyTextWithSubwordAi('Abhi unga p1n dalo warna acct bl0ck ho jayega');
  assert.equal(result.isScam, true);
  assert.ok(result.scamProbability >= 0.70);
});

// ═════════════════════════════════════════════════════════════════════════════
// 10. M1: MIXED-SCRIPT HOMOGLYPH & PUNYCODE DGA DETECTION
// ═════════════════════════════════════════════════════════════════════════════

test('M1.1: Mixed Latin-Cyrillic homoglyph domain flags as anomalous (anomalyScore >= 60)', () => {
  // 'micrоsoft.com' where 'о' is Cyrillic \u043E
  const res = computeLexicalAnomalyScore('micr\u043Esoft.com');
  assert.equal(res.isAnomalous, true);
  assert.ok(res.anomalyScore >= 60, `Expected score >= 60, got ${res.anomalyScore}`);
  assert.equal(res.details.isMixedScript, true);
});

test('M1.2: Mixed Greek-Latin homoglyph domain flags as anomalous', () => {
  // 'gооgle.com' with Greek omicron
  const res = computeLexicalAnomalyScore('g\u03BF\u03BFgle.com');
  assert.equal(res.isAnomalous, true);
  assert.ok(res.anomalyScore >= 60);
});

test('M1.3: Punycode encoded hostname flags with elevated lexical anomaly score', () => {
  const res = computeLexicalAnomalyScore('xn--e1afmkfd.xn--p1ai');
  assert.ok(res.anomalyScore >= 50, `Expected score >= 50, got ${res.anomalyScore}`);
  assert.equal(res.details.isPunycode, true);
});

test('M1.4: Normal ASCII domain remains non-anomalous (anomalyScore <= 30)', () => {
  const res = computeLexicalAnomalyScore('wikipedia.org');
  assert.equal(res.isAnomalous, false);
  assert.ok(res.anomalyScore <= 30);
  assert.equal(res.details.isMixedScript, false);
});

// ═════════════════════════════════════════════════════════════════════════════
// 11. M2: SECV MULTI-AXIS COERCION SYNERGY (E = 0)
// ═════════════════════════════════════════════════════════════════════════════

test('M2.1: Digital Arrest multi-axis intimidation notice without extraction (E = 0) triggers Coercion Boost', () => {
  const text = 'Inspector from CBI Crime Cell. Non-bailable arrest warrant issued. Police vehicle dispatched immediately to your address.';
  const secv = computeSecvIntentVector(text);
  assert.equal(secv.vector.E, 0, 'No extraction action present');
  assert.ok(secv.vector.A > 0, 'Authority active');
  assert.ok(secv.vector.C > 0, 'Catastrophe active');
  assert.ok(secv.vector.U > 0, 'Urgency active');
  assert.ok(secv.score >= 60, `Expected elevated coercion score >= 60, got ${secv.score}`);
  assert.ok(secv.synergy > 0, 'Multi-Axis Coercion Synergy Boost must fire when E = 0');
});

test('M2.2: Benign news conversation mentioning police arrest remains safe (score < 35, isConvergentScam = false)', () => {
  const text = 'Police arrested the thief in the news today. Let us watch the documentary video tonight.';
  const secv = computeSecvIntentVector(text);
  assert.equal(secv.isConvergentScam, false);
  assert.ok(secv.score < 35, `Expected score < 35, got ${secv.score}`);
});

// ═════════════════════════════════════════════════════════════════════════════
// 12. M4: EVIDENCE VAULT RING-BUFFER & QUOTA RESILIENCE
// ═════════════════════════════════════════════════════════════════════════════

test('M4.1: Evidence vault stores records and chains SHA-256 hashes correctly', async () => {
  globalThis.localStorage.clear();
  setVaultAnchorHash('0000000000000000000000000000000000000000000000000000000000000000');

  const rec1 = await saveRecordToVault({
    type: 'LINK',
    score: 95,
    severity: 'danger',
    snippet: 'https://phish.xyz'
  });
  const rec2 = await saveRecordToVault({
    type: 'UPI',
    score: 90,
    severity: 'danger',
    snippet: 'upi://pay?pa=fake@ybl'
  });

  assert.equal(rec2.prevHash, rec1.currentHash);
  const integrity = await verifyVaultChainIntegrity();
  assert.equal(integrity.valid, true);
  assert.equal(integrity.checkedCount, 2);
});

test('M4.2: Evidence vault evicts oldest records when exceeding MAX_VAULT_RECORDS and maintains anchor hash', async () => {
  globalThis.localStorage.clear();
  setVaultAnchorHash('0000000000000000000000000000000000000000000000000000000000000000');

  // Push 105 records into the vault
  for (let i = 0; i < 105; i++) {
    await saveRecordToVault({
      type: 'SCAN',
      score: i,
      severity: 'safe',
      snippet: `item-${i}`
    });
  }

  const vault = getVaultRecords();
  assert.equal(vault.length, MAX_VAULT_RECORDS);
  assert.notEqual(getVaultAnchorHash(), '0000000000000000000000000000000000000000000000000000000000000000');

  const integrity = await verifyVaultChainIntegrity();
  assert.equal(integrity.valid, true, 'Ring-buffer chain must remain cryptographically valid after eviction');
});

// ═════════════════════════════════════════════════════════════════════════════
// 13. M5: PARAMETER SANITIZATION
// ═════════════════════════════════════════════════════════════════════════════

test('M5.1: sanitizeSignalParams escapes HTML entities in parameter values', () => {
  const dirty = { brand: '<script>alert("xss")</script>', vpa: "hacker's&co" };
  const clean = sanitizeSignalParams(dirty);
  assert.equal(clean.brand, '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
  assert.equal(clean.vpa, 'hacker&#39;s&amp;co');
});

test('M5.2: sanitizeSignalParams strips ASCII control characters', () => {
  const dirty = { text: 'Hello\x00\x1FWorld\x7F' };
  const clean = sanitizeSignalParams(dirty);
  assert.equal(clean.text, 'HelloWorld');
});

// ═════════════════════════════════════════════════════════════════════════════
// 14. PERFORMANCE BENCHMARKS
// ═════════════════════════════════════════════════════════════════════════════

test('PERF.1: calculateRisk executes in < 5ms per evaluation', () => {
  const start = performance.now();
  const iterations = 50;
  for (let i = 0; i < iterations; i++) {
    calculateRisk('https://random-test-domain.top/login', [{ id: 'RULE_MISSING_HTTPS', score: 10 }]);
  }
  const elapsed = performance.now() - start;
  const avg = elapsed / iterations;
  assert.ok(avg < 5.0, `Average calculateRisk latency was ${avg.toFixed(3)}ms (expected < 5.0ms)`);
});

test('PERF.2: pureJsSha256 processes NIST vectors in < 2ms', () => {
  const start = performance.now();
  for (let i = 0; i < 50; i++) {
    pureJsSha256('verity-quick-hash-benchmark-vector');
  }
  const avg = (performance.now() - start) / 50;
  assert.ok(avg < 2.0, `Average SHA-256 latency was ${avg.toFixed(3)}ms (expected < 2.0ms)`);
});
