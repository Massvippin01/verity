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
import { isAllowlistedDomain } from '../shared/legit-domains.js';

// Load brands for rule checks
import brands from '../brands.json' with { type: 'json' };

function evaluateUrlOnly(url) {
  const ruleSignals = [
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
  return calculateRisk(url, ruleSignals, null, null, null, null, null, null, null, brands);
}

function evaluateFullPageWithLogin(url) {
  const ruleSignals = [
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

  const domSignals = {
    hasPasswordInput: true,
    loginFormCount: 1,
    formActions: [url],
    hasCredentialCollection: true,
    isTrustedDomain: false,
    paymentFields: {},
    hasPaymentForm: false,
    claimedProviders: [],
    pageText: 'Please log in to your account to continue',
    pageTitle: 'Sign In'
  };

  return calculateRisk(url, ruleSignals, 0, domSignals, null, null, null, null, null, brands);
}

test('Zero False Positives: 50+ Real-World Top Domains and Normal Sites must ALLOW (Score <= 25)', () => {
  const legitimateSites = [
    // 1. Media & News
    'https://fox.com',
    'https://www.foxnews.com',
    'https://vox.com',
    'https://www.theverge.com',
    'https://cnn.com',
    'https://bbc.com',
    'https://nytimes.com',
    'https://reuters.com',
    'https://wsj.com',
    'https://forbes.com',

    // 2. Travel & Booking
    'https://trip.com',
    'https://www.tripadvisor.com',
    'https://booking.com',
    'https://expedia.com',
    'https://airbnb.com',
    'https://kayak.com',

    // 3. Productivity & SaaS
    'https://loom.com',
    'https://zoom.us',
    'https://slack.com',
    'https://notion.so',
    'https://figma.com',
    'https://canva.com',
    'https://trello.com',
    'https://asana.com',
    'https://airtable.com',
    'https://miro.com',

    // 4. Financial & Payments (Clean official domains)
    'https://viva.com',
    'https://stripe.com',
    'https://paypal.com',
    'https://chase.com',
    'https://bankofamerica.com',
    'https://wellsfargo.com',
    'https://capitalone.com',

    // 5. Developer & Tech
    'https://github.com/login',
    'https://gitlab.com/users/sign_in',
    'https://stackoverflow.com/users/login',
    'https://npmjs.com/login',
    'https://docker.com',
    'https://cloudflare.com',

    // 6. Publishing & Creative
    'https://lulu.com',
    'https://medium.com/m/signin',
    'https://wordpress.com/log-in',
    'https://substack.com',
    'https://patreon.com',

    // 7. General Clean Sites
    'https://box.com',
    'https://dropbox.com',
    'https://weather.com',
    'https://vimeo.com',
    'https://dailymotion.com',
    'https://archive.org',
    'https://coursera.org',
    'https://khanacademy.org'
  ];

  for (const site of legitimateSites) {
    const verdict = evaluateUrlOnly(site);
    assert.strictEqual(
      verdict.action,
      'allow',
      `Expected ${site} to have action "allow", but got "${verdict.action}" with score ${verdict.score}. Reasons: ${verdict.reasons.join('; ')}`
    );
    assert.ok(
      verdict.score <= 25,
      `Expected ${site} score <= 25, but got ${verdict.score}`
    );
  }
});

test('Zero False Positives: Clean Enterprise and Corporate Login Pages must NOT trigger phishing blocks', () => {
  const normalCorporateLoginPages = [
    'https://portal.mycompany-intranet.com/account/login',
    'https://auth.enterprisesolutions.net/login',
    'https://internal-tools.org/signin',
    'https://hr-portal.co.uk/users/sign_in',
    'https://crm.localbusiness.de/account/login'
  ];

  for (const page of normalCorporateLoginPages) {
    const verdict = evaluateFullPageWithLogin(page);
    assert.notStrictEqual(
      verdict.action,
      'block',
      `Normal corporate login ${page} should not be blocked! Score: ${verdict.score}, Action: ${verdict.action}, Reasons: ${verdict.reasons.join('; ')}`
    );
    assert.ok(
      verdict.score < 70,
      `Normal corporate login ${page} should have score < 70, got ${verdict.score}`
    );
  }
});

test('Zero False Positives: Short-Word Brand Collision Guards', () => {
  // Verify fox vs box, loom vs zoom, viva vs visa, trip vs stripe
  const shortCollisions = [
    { url: 'https://fox.com', notBrand: 'Box' },
    { url: 'https://vox.com', notBrand: 'Box' },
    { url: 'https://loom.com', notBrand: 'Zoom' },
    { url: 'https://viva.com', notBrand: 'Visa' },
    { url: 'https://trip.com', notBrand: 'Stripe' }
  ];

  for (const item of shortCollisions) {
    const typosquat = detectTyposquatting(item.url, brands);
    assert.strictEqual(
      typosquat.triggered,
      false,
      `Domain ${item.url} should NOT be flagged as typosquatting ${item.notBrand}!`
    );

    const verdict = evaluateUrlOnly(item.url);
    assert.strictEqual(verdict.action, 'allow');
    assert.strictEqual(verdict.score, 0);
  }
});
