import test from 'node:test';
import assert from 'node:assert/strict';
import { checkDomainAge } from '../background/domain-age.js';
import { calculateRisk } from '../background/risk-engine.js';
import { isAllowlistedDomain } from '../shared/legit-domains.js';

test('Domain Age: allowlisted domains are never flagged by domain age check', async () => {
  const result = await checkDomainAge('https://www.google.com/search?q=test');
  assert.equal(result.triggered, false);
  assert.equal(result.score, 0);

  const bankResult = await checkDomainAge('https://netbanking.hdfcbank.com/login');
  assert.equal(bankResult.triggered, false);
});

test('Domain Age: long-established domain (wikipedia.org) is not flagged', async () => {
  const result = await checkDomainAge('https://en.wikipedia.org/wiki/Main_Page');
  assert.equal(result.triggered, false);
  assert.equal(result.score, 0);
});

test('Domain Age: newly registered domain signal integrates properly with risk engine', () => {
  const nrdSignal = {
    id: 'SIG_NEWLY_REGISTERED_DOMAIN',
    params: { ageDays: 3, domain: 'ephemeral-secure-login.com' },
    score: 40,
    triggered: true,
    reason: 'Newly registered domain (3 days old).'
  };

  const brandSignal = {
    id: 'RULE_BRAND_VARIANT_MATCH',
    params: { brand: 'PayPal' },
    score: 65,
    triggered: true,
    reason: 'Hostname matches known typosquat variant of PayPal.'
  };

  // Case A: URL alone (NRD + Brand) without DOM evidence demotes to Caution (65) per single-source convergence
  const singleSourceVerdict = calculateRisk(
    'https://ephemeral-secure-login.com/paypal/signin',
    [nrdSignal, brandSignal],
    null,
    null
  );
  assert.equal(singleSourceVerdict.action, 'warn');
  assert.equal(singleSourceVerdict.severity, 'caution');
  assert.equal(singleSourceVerdict.score, 65);

  // Case B: NRD + Brand corroborated by DOM credential form reaches BLOCK
  const domSignals = {
    hasCredentialCollection: true,
    hasPasswordInput: true,
    loginFormCount: 1
  };
  const twoSourceVerdict = calculateRisk(
    'https://ephemeral-secure-login.com/paypal/signin',
    [nrdSignal, brandSignal],
    null,
    domSignals
  );

  assert.ok(twoSourceVerdict.score >= 70, `Score must be >= 70 with brand spoof on NRD + credential form, got: ${twoSourceVerdict.score}`);
  assert.equal(twoSourceVerdict.action, 'block');
  assert.equal(twoSourceVerdict.severity, 'danger');
});
