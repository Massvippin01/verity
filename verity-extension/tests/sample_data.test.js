import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanText } from '../shared/text-scanner.js';
import brands from '../brands.json' with { type: 'json' };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Locate test cases json in sample_data directory
const possiblePaths = [
  path.resolve(__dirname, '../sample_data/indian_cyber_fraud_test_cases.json'),
  path.resolve(__dirname, '../../sample_data/indian_cyber_fraud_test_cases.json')
];

let testCasesPath = possiblePaths.find(p => fs.existsSync(p));
if (!testCasesPath) {
  throw new Error('Could not find sample_data/indian_cyber_fraud_test_cases.json');
}

const testCases = JSON.parse(fs.readFileSync(testCasesPath, 'utf8'));

test('Sample Data: Validates all 30 Indian Cyber Fraud cases against scanText', (t) => {
  let scamCount = 0;
  let detectedScamCount = 0;
  let legitCount = 0;
  let falsePositiveCount = 0;
  const failures = [];

  for (const tc of testCases) {
    const isLegit = tc.category === 'legitimate_portal';
    if (isLegit) {
      legitCount++;
    } else {
      scamCount++;
    }

    const result = scanText(tc.input, { brandsList: brands });

    const verdictMatched = result.verdict === tc.expectedVerdict;
    if (isLegit) {
      if (result.verdict !== 'safe') {
        falsePositiveCount++;
        failures.push({
          id: tc.id,
          category: tc.category,
          input: tc.input,
          expected: tc.expectedVerdict,
          actual: result.verdict,
          score: result.score,
          signals: result.signals.map(s => s.id)
        });
      }
    } else {
      if (result.verdict === 'danger') {
        detectedScamCount++;
      } else {
        failures.push({
          id: tc.id,
          category: tc.category,
          input: tc.input,
          expected: tc.expectedVerdict,
          actual: result.verdict,
          score: result.score,
          signals: result.signals.map(s => s.id)
        });
      }
    }

    // Verify expected signals if specified
    if (tc.expectedSignals && tc.expectedSignals.length > 0) {
      const hasExpectedSignal = tc.expectedSignals.some(expectedSig =>
        result.signals.some(s => s.id === expectedSig)
      );
      if (!hasExpectedSignal) {
        failures.push({
          id: tc.id,
          type: 'SIGNAL_MISMATCH',
          expectedSignals: tc.expectedSignals,
          actualSignals: result.signals.map(s => s.id)
        });
      }
    }
  }

  // Print summary to stdout as required by specification
  console.log('\n===============================================================');
  console.log('📊 VERITY SAMPLE DATASET EVALUATION SUMMARY');
  console.log('===============================================================');
  console.log(`Total Cases Evaluated: ${testCases.length}`);
  console.log(`Scams Detected:       ${detectedScamCount} / ${scamCount} (${((detectedScamCount / scamCount) * 100).toFixed(1)}%)`);
  console.log(`Legitimate Portals:   ${legitCount}`);
  console.log(`False Positives:       ${falsePositiveCount} / ${legitCount} (Target: 0)`);
  console.log('===============================================================\n');

  if (failures.length > 0) {
    console.error('❌ Sample Data Failures:');
    for (const f of failures) {
      console.error(JSON.stringify(f, null, 2));
    }
  }

  // Strict assertions
  assert.equal(failures.length, 0, `Expected 0 failures, got ${failures.length}`);
  assert.equal(detectedScamCount, scamCount, `Expected all ${scamCount} scams to be detected`);
  assert.equal(falsePositiveCount, 0, 'False positives on legitimate portals must be exactly 0');
});

// Run each individual case as a sub-test for granular reporting
for (const tc of testCases) {
  test(`Sample Case [${tc.id}] (${tc.category}): ${tc.input.slice(0, 50)}...`, () => {
    const result = scanText(tc.input, { brandsList: brands });
    assert.equal(
      result.verdict,
      tc.expectedVerdict,
      `Case ${tc.id} failed: expected ${tc.expectedVerdict}, got ${result.verdict} (score: ${result.score}) for input: "${tc.input}"`
    );

    if (tc.expectedVerdict === 'danger' && tc.expectedSignals && tc.expectedSignals.length > 0) {
      const hasSignal = tc.expectedSignals.some(expectedSig =>
        result.signals.some(s => s.id === expectedSig)
      );
      assert.ok(
        hasSignal,
        `Case ${tc.id} missing expected signals ${tc.expectedSignals.join(', ')}. Got: ${result.signals.map(s => s.id).join(', ')}`
      );
    }
  });
}
