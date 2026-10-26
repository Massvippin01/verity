import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { scanText } from '../shared/text-scanner.js';
import { validateVerdictContract } from '../shared/verdict-contract.js';
import { getRecoveryGuide, sanitizeSecrets, generateEvidenceReceipt } from '../shared/recovery-advisor.js';
import brands from '../brands.json' with { type: 'json' };

const fixturesPath = path.resolve('../sample_data/combinatorial_scenarios_matrix.json');
const rawFixtures = fs.readFileSync(fixturesPath, 'utf8');
const fixtures = JSON.parse(rawFixtures);

test('Combinatorial Permutations: 1. Machine-readable matrix fixture schema validation', () => {
  assert.ok(Array.isArray(fixtures) && fixtures.length >= 10);
  for (const item of fixtures) {
    assert.ok(item.scenarioId, 'Missing scenarioId');
    assert.ok(item.threatCategory, 'Missing threatCategory');
    assert.ok(item.inputModality, 'Missing inputModality');
    assert.ok(item.expectedVerdict, 'Missing expectedVerdict');
  }
});

test('Combinatorial Permutations: 2. Execution across multi-dimensional combinations', () => {
  for (const scenario of fixtures) {
    if (scenario.expectedVerdict === 'HIGH_RISK') {
      const res = scanText(scenario.inputFixture, { brandsList: brands });
      assert.ok(res.verdictContract, `Missing verdictContract for ${scenario.scenarioId}`);
      assert.equal(res.verdict, 'danger', `Scenario ${scenario.scenarioId} expected danger`);
      assert.equal(res.verdictContract.riskClassification, 'HIGH_RISK');
    } else if (scenario.expectedVerdict === 'SAFE') {
      const res = scanText(scenario.inputFixture, { brandsList: brands });
      assert.ok(res.verdictContract);
      assert.equal(res.verdict, 'safe', `Scenario ${scenario.scenarioId} expected safe`);
      assert.equal(res.verdictContract.riskClassification, 'SAFE');
      assert.equal(res.score, 0);
    } else if (scenario.expectedVerdict === 'ABSTAIN') {
      const res = scanText(scenario.inputFixture, { brandsList: brands });
      assert.ok(res.verdictContract);
      // Benign message with zero indicators should not be marked HIGH_RISK
      assert.ok(res.score <= 30);
    }
  }
});

test('Combinatorial Permutations: 3. Post-Action Recovery Combinations across Tamil, Hindi, Telugu', () => {
  const recoveryScenarios = [
    { incident: 'APPROVED_PAYMENT_OR_TRANSFERRED', lang: 'ta', keyword: '1930' },
    { incident: 'SHARED_OTP_OR_PIN', lang: 'hi', keyword: '1930' },
    { incident: 'INSTALLED_SUSPICIOUS_APP', lang: 'te', keyword: 'Safe Mode' },
    { incident: 'EXTORTION_OR_DIGITAL_ARREST', lang: 'ta', keyword: 'டிஜிட்டல் கைது' }
  ];

  for (const item of recoveryScenarios) {
    const guide = getRecoveryGuide(item.incident, item.lang);
    assert.ok(guide.steps.length >= 3);
    const combinedSteps = guide.steps.join(' ');
    assert.ok(combinedSteps.includes(item.keyword), `Expected keyword "${item.keyword}" in ${item.incident} (${item.lang})`);
  }
});

test('Combinatorial Permutations: 4. Sensitive Information Redaction Property Test', () => {
  const testInputs = [
    { raw: 'Paid via 4111222233334444', shouldNotContain: '4111222233334444', shouldContain: '****-****-****-4444' },
    { raw: 'Aadhaar 9999 8888 7777 verified', shouldNotContain: '9999 8888 7777', shouldContain: 'XXXX-XXXX-7777' },
    { raw: 'My password: SecretPass123! entered', shouldNotContain: 'SecretPass123!', shouldContain: '[REDACTED_PASSWORD]' },
    { raw: 'OTP: 654321 approved', shouldNotContain: '654321', shouldContain: '[REDACTED_PIN]' }
  ];

  for (const item of testInputs) {
    const sanitized = sanitizeSecrets(item.raw);
    assert.ok(!sanitized.includes(item.shouldNotContain), `Failed to mask ${item.shouldNotContain}`);
    assert.ok(sanitized.includes(item.shouldContain), `Expected ${item.shouldContain} in ${sanitized}`);
  }
});
