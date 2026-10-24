import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateRisk } from '../background/risk-engine.js';
import {
  isIpBasedUrl,
  hasMissingHttps,
  hasExcessiveSubdomains,
  hasBrandNameInWrongDomain,
  hasSuspiciousUrlPattern,
  hasPunycodeOrKeywords,
  hasFinancialKeywordInHostname,
  hasBrandVariantMatch,
  hasMalvertisingPattern,
  hasRandomLookingHostname,
  hasAffiliateTrackerPattern,
  hasPiracyOrUnverifiedMediaPattern,
  hasAitmProxyUrlSignature,
  hasHomographAttack
} from '../background/rules.js';
import { detectTyposquatting } from '../background/brand-detector.js';
import brands from '../brands.json' with { type: 'json' };
import { scanText as extScanText } from '../shared/text-scanner.js';
import { scanText as mobScanText } from '../../mobile-scanner/core/shared/text-scanner.js';

function buildRules(url) {
  return [
    isIpBasedUrl(url),
    hasMissingHttps(url),
    hasExcessiveSubdomains(url),
    hasBrandNameInWrongDomain(url, brands),
    hasSuspiciousUrlPattern(url),
    hasPunycodeOrKeywords(url),
    detectTyposquatting(url, brands),
    hasFinancialKeywordInHostname(url, brands),
    hasBrandVariantMatch(url, brands),
    hasMalvertisingPattern(url),
    hasRandomLookingHostname(url),
    hasAffiliateTrackerPattern(url),
    hasPiracyOrUnverifiedMediaPattern(url),
    hasAitmProxyUrlSignature(url),
    hasHomographAttack(url, brands)
  ];
}

const BITDEFENDER_WILD_URL_1 = 'https://eifitcannotke.org/Q3pLd28iGCgaUCJHKVEaMRZ2Ul0FX3kxC3ASfwEbMU0qDwI7STtZDC8VPhMJMRUlA0EtHz9SXQU/HTM9Di54EFwUAwIHPTo4LzwnCTASADV6H3s1GwYQPE4nFzMBPCwCKgQbCCk2Iw9ZFCkGQioXPAMnLHccBiUAczQsPRYbEHMQKSorATwuNAoFAD4aMyM+DhQTAiAscDAKOQY3PBIlH3YbGSZeFBM/DisHLxg8PAYYKiY5MjYjAF0AIiMHKwAoKT1cCjQbRjYsMwoyGxQAIB43KjwdFDwKIgcbXyQzMxsXAR07QTkuKxkRAXorAkZfKjEzFAURSGYbVhA+OzYOG0sCLT4REy1GXi0eJhtWEDkFEyYtFgYUPiA1KhwfKC4DB1gWIg4wCQBOAj0pJAoENV9xIjIiWBstEQ4KGwIbEggnTCocHygyCBQBBz4nLg4bSnwUPhlCAg8qZkgNIjgvQxgzIRE2MiY3JSgNUl0BHDMEVxETBh4nGz8MNAF2NBIlH3sjHh9ZAT0nTjwAHh08BncxGyUpZkgJNDpyFApFJXsuJT0tICJ/UQUwFSUHUic5GhRfFxchOQEtIzg';
const BITDEFENDER_WILD_URL_2 = 'https://login.ipkopl.com/auth/login.php';

test('Real-World Bitdefender Threat 1 (GT:JS.Adware.Acsogenixx): Obfuscated Script & DGA must BLOCK', () => {
  const rules = buildRules(BITDEFENDER_WILD_URL_1);
  const verdict = calculateRisk(BITDEFENDER_WILD_URL_1, rules, 0, null, null, null, null, null, 1.0, brands);

  assert.strictEqual(verdict.action, 'block', 'eifitcannotke.org malicious JS adware payload must be blocked');
  assert.strictEqual(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85, `Score must be >= 85, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'RULE_MALVERTISING_REDIRECT'), 'Must flag RULE_MALVERTISING_REDIRECT');
  assert.ok(verdict.signals.some(s => s.id === 'RULE_RANDOM_LOOKING_HOSTNAME'), 'Must flag RULE_RANDOM_LOOKING_HOSTNAME');

  // Root domain also flagged as suspicious DGA
  const rootDga = hasRandomLookingHostname('https://eifitcannotke.org');
  assert.strictEqual(rootDga.triggered, true, 'eifitcannotke.org root domain must be flagged as DGA');
});

test('Real-World Bitdefender Threat 2 (Fraudulent Page): iPKO Bank Combosquat Phishing must BLOCK', () => {
  const rules = buildRules(BITDEFENDER_WILD_URL_2);
  const verdict = calculateRisk(BITDEFENDER_WILD_URL_2, rules, 0, null, null, null, null, null, 1.0, brands);

  assert.strictEqual(verdict.action, 'block', 'login.ipkopl.com credential phishing portal must be blocked');
  assert.strictEqual(verdict.severity, 'danger');
  assert.ok(verdict.score >= 95, `Score must be >= 95 for brand credential portal trap, got ${verdict.score}`);
  assert.ok(verdict.signals.some(s => s.id === 'RULE_BRAND_NAME_WRONG_DOMAIN'), 'Must flag brand impersonation of iPKO');
  assert.ok(verdict.signals.some(s => s.id === 'RULE_BRAND_VARIANT_MATCH'), 'Must flag brand variant match');
});

test('Scanner Parity: Extension and Mobile Citizen Scanner both block real-world threats with 100/100 danger', () => {
  const extResult1 = extScanText(BITDEFENDER_WILD_URL_1, { brandsList: brands });
  const mobResult1 = mobScanText(BITDEFENDER_WILD_URL_1, { brandsList: brands });

  assert.strictEqual(extResult1.verdict, 'danger');
  assert.strictEqual(mobResult1.verdict, 'danger');
  assert.ok(extResult1.score >= 85);
  assert.ok(mobResult1.score >= 85);

  const extResult2 = extScanText(BITDEFENDER_WILD_URL_2, { brandsList: brands });
  const mobResult2 = mobScanText(BITDEFENDER_WILD_URL_2, { brandsList: brands });

  assert.strictEqual(extResult2.verdict, 'danger');
  assert.strictEqual(mobResult2.verdict, 'danger');
  assert.ok(extResult2.score >= 95);
  assert.ok(mobResult2.score >= 95);
  assert.strictEqual(extResult2.goldenRuleKey, 'otp_password');
  assert.strictEqual(mobResult2.goldenRuleKey, 'otp_password');
});

test('Zero False Positives: Official European Banking Domains remain 100% safe', () => {
  const legitUrls = [
    'https://ipko.pl',
    'https://pkobp.pl',
    'https://www.pkobp.pl/strefa-klienta',
    'https://mbank.pl',
    'https://santander.pl',
    'https://ing.pl'
  ];

  for (const url of legitUrls) {
    const rules = buildRules(url);
    const verdict = calculateRisk(url, rules, 0, null, null, null, null, null, 1.0, brands);
    assert.strictEqual(verdict.action, 'allow', `Legit banking domain ${url} must be allowed`);
    assert.strictEqual(verdict.score, 0, `Legit banking domain ${url} must score 0`);
  }
});
