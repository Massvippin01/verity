/**
 * tests/verify_malvertising_redirect_rotator.js
 *
 * Verifies end-to-end defense against fast client-side malvertising redirect rotators
 * and multi-hop obfuscated rotator chains (e.g., werefilledwit.org -> ljline.com).
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { hasMalvertisingPattern, hasAffiliateTrackerPattern } from '../background/rules.js';
import { calculateRisk } from '../background/risk-engine.js';
import { recordHop, getRedirectSignals, pruneTab } from '../background/redirect-analyzer.js';

const ROTATOR_BRIDGE_URL = 'https://werefilledwit.org/RVV1SzVqahY4CBACBSZgAhseHgRwPyN5cxYARwFmHxNEGm8pAFMqVzFoQW1HIDFIehM2OEh6A2M+SG1DeGRbeAFrZk1lAmMmATgIdXMFOVt4ZVMuWCdoRW1BLDFIegJ3ZEFzDGMnDTIIdGBGfWp9Y0FtXCs2SHMTMGhEcwF9YEFyBHFtRHMCcWFEbVQiMBZ2BHJsRHMFcGFMeRMjJkh6EzcwE3ZdMSEFOBB2FFB5c2BnMy9aMjsZJFQhexgkQywwBjtUIjBbM0w/cEcNUSoiGydaJDFQeXMjPBkuEHcTRHsHcGRGbV82IUh7EyA7B3YFYzkWPlR4OBoxXCk5FG4HA2BbexB3ZV08XCsxGjxGYGdFJUFgZ0V6BWtlUHh3YGdFPFwrY0FuBgdwR3tNc2Fcbgd1NAU7WSAiECleLCFQeXNwZkJlBnNwR3sdLj0BJllgZzZuB3U5HCBQYGdFLFAmPhpiEHdlFiNHKjgQbgcDZEB+G3V7RWUFYGdFOFQjNAciEHcTQHgCa2ZDbUYgNgUnVDFoIiJbIToCOBM2MBY7WSQhAy5HeGRMZQVrZVM4UCYzAycIYGdHDFoqMhkuEHdlNiNHKjgQbgd3cEYJQ2BmMW4Hd2RAfht1e017AHx7QXoQd2dQeXZgZ0VuB3cWHTlaKDwAJhB3Z1B4dzNwRg8Qd2dEfgBrZVtzBXBsW38EYGdHbgcGcEd7EHdnOyRBbRRQeHQHJxQlUWBnR24GByNQeHFgZ0d5AWtlW3sbdXBHeRM2MBYmWiEwGXYTMS8RdgBrYFM+WSo2SD9UYzwTdgVjNgF2BmM2ASgIfA';
const ROTATOR_DESTINATION_URL = 'https://ljline.com/iI0156mcDUnDMLQ/151718?param_4=1721489&param_5=5033194268461371774';

test('Malvertising Rotator Case 1: Initial bridge (werefilledwit.org) must trigger BLOCK (Score >= 85)', () => {
  const malv = hasMalvertisingPattern(ROTATOR_BRIDGE_URL);
  assert.equal(malv.triggered, true, 'werefilledwit.org should trigger hasMalvertisingPattern');
  assert.ok(malv.score >= 80, `Expected malvertising score >= 80, got ${malv.score}`);

  const risk = calculateRisk(ROTATOR_BRIDGE_URL, [malv], 0, null, null, null);
  console.log('\n--- Case 1: werefilledwit.org Rotator Bridge ---');
  console.log('Action:', risk.action, '| Score:', risk.score, '| Severity:', risk.severity);
  console.log('Reasons:', risk.reasons);
  assert.equal(risk.action, 'block');
  assert.equal(risk.severity, 'danger');
  assert.ok(risk.score >= 85, `Score ${risk.score} should be >= 85`);
});

test('Malvertising Rotator Case 2: Second redirect destination (ljline.com) in isolation must trigger BLOCK (Score >= 85)', () => {
  const malv = hasMalvertisingPattern(ROTATOR_DESTINATION_URL);
  const aff = hasAffiliateTrackerPattern(ROTATOR_DESTINATION_URL);

  assert.equal(malv.triggered, true, 'ljline.com should trigger hasMalvertisingPattern for mixed-case shard token + numeric zone');
  assert.equal(aff.triggered, true, 'ljline.com should trigger hasAffiliateTrackerPattern for param_4, param_5 and large integer tracker ID');

  const risk = calculateRisk(ROTATOR_DESTINATION_URL, [malv, aff], 0, null, null, null);
  console.log('\n--- Case 2: ljline.com Destination In Isolation ---');
  console.log('Action:', risk.action, '| Score:', risk.score, '| Severity:', risk.severity);
  console.log('Reasons:', risk.reasons);
  assert.equal(risk.action, 'block');
  assert.equal(risk.severity, 'danger');
  assert.ok(risk.score >= 85, `Score ${risk.score} should be >= 85`);
});

test('Malvertising Rotator Case 3: Redirect chain taint propagation (werefilledwit.org -> clean destination)', () => {
  const tabId = 98765;
  pruneTab(tabId);

  // Simulate tab navigating to werefilledwit.org, then client-side redirecting to a clean-looking destination
  const cleanDestination = 'https://clean-landing-trap.com/welcome';
  recordHop(tabId, ROTATOR_BRIDGE_URL, false);
  recordHop(tabId, cleanDestination, false);

  const redirectSignals = getRedirectSignals(tabId);
  assert.ok(redirectSignals, 'Redirect signals should be generated');
  assert.equal(redirectSignals.suspiciousIntermediateDomain, true, 'Should flag suspicious intermediate domain');

  const malvRedirectSignal = redirectSignals.structuredReasons.find(r => r.id === 'SIG_MALVERTISING_REDIRECT');
  assert.ok(malvRedirectSignal, 'Should emit SIG_MALVERTISING_REDIRECT in structuredReasons');
  assert.equal(malvRedirectSignal.category, 'malvertising');
  assert.ok(malvRedirectSignal.score >= 70);

  const risk = calculateRisk(cleanDestination, [], 0, null, null, redirectSignals);
  console.log('\n--- Case 3: Clean Destination via Malvertising Hop ---');
  console.log('Action:', risk.action, '| Score:', risk.score, '| Severity:', risk.severity);
  console.log('Reasons:', risk.reasons);
  assert.equal(risk.action, 'block', 'Clean destination must inherit BLOCK verdict from malvertising hop');
  assert.equal(risk.severity, 'danger');
  assert.ok(risk.score >= 85, `Score ${risk.score} should be >= 85`);
});

test('Malvertising Rotator Case 4: Synchronous content script heuristic check', () => {
  function isImmediateMalvertisingRotator(urlStr) {
    if (!urlStr) return false;
    try {
      const u = new URL(urlStr);
      const fullPath = u.pathname + u.search;
      if (fullPath.length > 300 || /[A-Za-z0-9_\-*%]{80,}/.test(u.pathname)) {
        return true;
      }
      if (/^\?[a-f0-9]{16,64}$/i.test(u.search)) {
        return true;
      }
      const segments = u.pathname.split('/').filter(Boolean);
      const hasMixedSeg = segments.some(s => s.length >= 10 && s.length <= 35 && /[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s));
      const hasNumericCampaign = segments.some(s => /^[0-9]{4,10}$/.test(s));
      const hasParamN = Array.from(u.searchParams.keys()).some(k => /^param_[0-9]+$/i.test(k));
      if (hasMixedSeg && (hasNumericCampaign || hasParamN)) {
        return true;
      }
    } catch (_) {}
    return false;
  }

  assert.equal(isImmediateMalvertisingRotator(ROTATOR_BRIDGE_URL), true, 'Bridge URL must be caught synchronously');
  assert.equal(isImmediateMalvertisingRotator(ROTATOR_DESTINATION_URL), true, 'Destination URL must be caught synchronously');

  // Verify legitimate sites are NEVER caught
  assert.equal(isImmediateMalvertisingRotator('https://www.google.com/search?q=verity+extension'), false);
  assert.equal(isImmediateMalvertisingRotator('https://github.com/google/verity/pull/42'), false);
  assert.equal(isImmediateMalvertisingRotator('https://www.youtube-nocookie.com/embed/UsmiRIozzvw'), false);
  assert.equal(isImmediateMalvertisingRotator('https://en.wikipedia.org/wiki/Computer_security'), false);
  assert.equal(isImmediateMalvertisingRotator('https://store.example.com/item/casual-summer-shoes-blue'), false);
});
