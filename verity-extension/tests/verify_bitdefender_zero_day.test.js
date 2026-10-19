import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateRisk } from '../background/risk-engine.js';
import { detectFaviconSpoof, murmurHash3 } from '../background/favicon-matcher.js';
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

test('Bitdefender-Tier Zero-Day 1: Cloned Favicon MurmurHash3 Attack on Zero-Day Domain must BLOCK', () => {
  // Attack Case 1: Zero-day phishing kit cloning official Microsoft Favicon (hash: 1848946384)
  const msPhishUrl = 'https://login-verify-account8819.top/auth';
  const msDomSignals = {
    faviconHash: 1848946384,
    hasPasswordInput: true,
    loginFormCount: 1,
    hasCredentialCollection: true,
    isTrustedDomain: false,
    pageTitle: 'Sign In to Your Account'
  };

  const msVerdict = calculateRisk(
    msPhishUrl,
    buildRules(msPhishUrl),
    0,
    msDomSignals,
    null,
    null,
    null,
    null,
    null,
    brands
  );

  assert.strictEqual(msVerdict.action, 'block', `Cloned Microsoft favicon phishing kit must be blocked! Got: ${msVerdict.action}`);
  assert.ok(msVerdict.score >= 95, `Risk score must be >= 95 for favicon clone + credentials. Got: ${msVerdict.score}`);
  assert.ok(
    msVerdict.signals.some(s => s.id === 'SIG_FAVICON_BRAND_SPOOF'),
    'Must emit SIG_FAVICON_BRAND_SPOOF signal'
  );

  // Attack Case 2: Zero-day phishing kit cloning PayPal Favicon (hash: -1107577557)
  const paypalPhishUrl = 'https://security-notice-update83.xyz/login';
  const ppDomSignals = {
    faviconHash: -1107577557,
    hasPasswordInput: true,
    loginFormCount: 1,
    hasCredentialCollection: true,
    isTrustedDomain: false,
    pageTitle: 'Log in to your PayPal account'
  };

  const ppVerdict = calculateRisk(
    paypalPhishUrl,
    buildRules(paypalPhishUrl),
    0,
    ppDomSignals,
    null,
    null,
    null,
    null,
    null,
    brands
  );

  assert.strictEqual(ppVerdict.action, 'block', `Cloned PayPal favicon phishing kit must be blocked! Got: ${ppVerdict.action}`);
  assert.ok(ppVerdict.score >= 95, `Risk score must be >= 95. Got: ${ppVerdict.score}`);
  assert.ok(
    ppVerdict.signals.some(s => s.id === 'SIG_FAVICON_BRAND_SPOOF'),
    'Must emit SIG_FAVICON_BRAND_SPOOF signal'
  );

  // Legit Check: Official domain with its own favicon must never trigger spoof
  const officialMsSpoof = detectFaviconSpoof('https://login.live.com', { faviconHash: 1848946384 }, brands);
  assert.strictEqual(officialMsSpoof.triggered, false, 'Official domain must never flag its own favicon hash as spoofed');
});

test('Bitdefender-Tier Zero-Day 2: Official CDN Favicon Hotlink on Unverified Domain must BLOCK', () => {
  const hotlinkUrl = 'https://verify-billing-status.fun/payment';
  const domSignals = {
    brandAssetUrls: ['https://paypalobjects.com/webstatic/icon/favicon.ico'],
    hasPasswordInput: true,
    hasCredentialCollection: true,
    isTrustedDomain: false,
    pageTitle: 'PayPal Billing Verification'
  };

  const verdict = calculateRisk(
    hotlinkUrl,
    buildRules(hotlinkUrl),
    0,
    domSignals,
    null,
    null,
    null,
    null,
    null,
    brands
  );

  assert.strictEqual(verdict.action, 'block', `Hotlinked official brand CDN favicon must be blocked! Got: ${verdict.action}`);
  assert.ok(verdict.score >= 90, `Risk score must be >= 90. Got: ${verdict.score}`);
  assert.ok(
    verdict.signals.some(s => s.id === 'SIG_FAVICON_BRAND_SPOOF'),
    'Must emit SIG_FAVICON_BRAND_SPOOF signal'
  );
});

test('Bitdefender-Tier Zero-Day 3: Free Hosting Credential Harvesting Trap must BLOCK', () => {
  // Case A: Cloudflare Pages phishing kit with credential form
  const pagesDevUrl = 'https://paypal-security-update.pages.dev/login';
  const pagesDom = {
    hasPasswordInput: true,
    hasCredentialCollection: true,
    loginFormCount: 1,
    freeHostingCredentialTrap: true,
    freeHostingPlatform: 'pages.dev',
    freeHostingReason: 'Credential collection or sensitive input detected on multi-tenant free hosting (pages.dev)',
    isTrustedDomain: false,
    pageTitle: 'Log In'
  };

  const pagesVerdict = calculateRisk(
    pagesDevUrl,
    buildRules(pagesDevUrl),
    0,
    pagesDom,
    null,
    null,
    null,
    null,
    null,
    brands
  );

  assert.strictEqual(pagesVerdict.action, 'block', `Credential trap on pages.dev must be blocked! Got: ${pagesVerdict.action}`);
  assert.ok(pagesVerdict.score >= 90, `Score must be >= 90. Got: ${pagesVerdict.score}`);
  assert.ok(
    pagesVerdict.signals.some(s => s.id === 'SIG_FREE_HOSTING_CREDENTIAL_TRAP'),
    'Must emit SIG_FREE_HOSTING_CREDENTIAL_TRAP signal'
  );

  // Case B: Firebase Web App phishing kit with banking credential form
  const webAppUrl = 'https://wells-fargo-auth.web.app/account';
  const webAppDom = {
    hasPasswordInput: true,
    hasCredentialCollection: true,
    loginFormCount: 1,
    freeHostingCredentialTrap: true,
    freeHostingPlatform: 'web.app',
    freeHostingReason: 'Credential collection or sensitive input detected on multi-tenant free hosting (web.app)',
    isTrustedDomain: false,
    pageTitle: 'Wells Fargo Sign On'
  };

  const webAppVerdict = calculateRisk(
    webAppUrl,
    buildRules(webAppUrl),
    0,
    webAppDom,
    null,
    null,
    null,
    null,
    null,
    brands
  );

  assert.strictEqual(webAppVerdict.action, 'block', `Credential trap on web.app must be blocked! Got: ${webAppVerdict.action}`);
  assert.ok(webAppVerdict.score >= 90, `Score must be >= 90. Got: ${webAppVerdict.score}`);

  // Case C: Clean Portfolio on free hosting without credentials must ALLOW
  const cleanPortfolioUrl = 'https://developer-john.github.io/portfolio';
  const cleanPortfolioDom = {
    hasPasswordInput: false,
    hasCredentialCollection: false,
    loginFormCount: 0,
    freeHostingCredentialTrap: false,
    isTrustedDomain: false,
    pageTitle: 'John Doe - Portfolio'
  };

  const cleanPortfolioVerdict = calculateRisk(
    cleanPortfolioUrl,
    buildRules(cleanPortfolioUrl),
    0,
    cleanPortfolioDom,
    null,
    null,
    null,
    null,
    null,
    brands
  );

  assert.strictEqual(cleanPortfolioVerdict.action, 'allow', `Clean portfolio must be allowed! Got: ${cleanPortfolioVerdict.action}`);
  assert.ok(cleanPortfolioVerdict.score <= 25, `Clean portfolio score must be <= 25. Got: ${cleanPortfolioVerdict.score}`);
});

test('Bitdefender-Tier Zero-Day 4: Phishing Kit Anti-Analysis Evasion Techniques', () => {
  const evasionUrl = 'https://account-security-alert83.live/auth';
  const evasionDom = {
    hasPasswordInput: true,
    hasCredentialCollection: true,
    loginFormCount: 1,
    evasionTechniqueDetected: true,
    evasionTechniqueReason: 'Right-click contextmenu disabled on sensitive credential entry page',
    isTrustedDomain: false,
    pageTitle: 'Sign In'
  };

  const verdict = calculateRisk(
    evasionUrl,
    buildRules(evasionUrl),
    0,
    evasionDom,
    null,
    null,
    null,
    null,
    null,
    brands
  );

  assert.ok(
    verdict.signals.some(s => s.id === 'SIG_EVASION_TECHNIQUE_DETECTED'),
    'Must emit SIG_EVASION_TECHNIQUE_DETECTED signal'
  );
  assert.ok(verdict.score >= 70, `Score must reach Block threshold >= 70 with credential input + evasion. Got: ${verdict.score}`);
  assert.strictEqual(verdict.action, 'block');
});

test('Bitdefender-Tier Zero-Day 5: High-Profile Brand Catalog Additions (Steam, Roblox, Phantom)', () => {
  // Steam official domain: ALLOW
  const steamOfficial = calculateRisk('https://steampowered.com/app/10', buildRules('https://steampowered.com/app/10'), 0, null, null, null, null, null, null, brands);
  assert.strictEqual(steamOfficial.action, 'allow');
  assert.strictEqual(steamOfficial.score, 0);

  // Steam typosquat / phishing clone: BLOCK
  const steamPhishUrl = 'https://steamcommunity-trade-offers.com/login';
  const steamPhish = calculateRisk(steamPhishUrl, buildRules(steamPhishUrl), 0, { hasPasswordInput: true, hasCredentialCollection: true }, null, null, null, null, null, brands);
  assert.strictEqual(steamPhish.action, 'block', `Steam phishing domain must be blocked! Got: ${steamPhish.action}`);
  assert.ok(steamPhish.score >= 85, `Score must be >= 85. Got: ${steamPhish.score}`);

  // Roblox phishing: BLOCK
  const robloxPhishUrl = 'https://roblox-free-robux-claim.com';
  const robloxPhish = calculateRisk(robloxPhishUrl, buildRules(robloxPhishUrl), 0, { hasCredentialCollection: true }, null, null, null, null, null, brands);
  assert.strictEqual(robloxPhish.action, 'block', `Roblox phishing domain must be blocked! Got: ${robloxPhish.action}`);

  // Phantom wallet crypto phishing: BLOCK
  const phantomPhishUrl = 'https://phantom-app-wallet.com/connect';
  const phantomPhish = calculateRisk(phantomPhishUrl, buildRules(phantomPhishUrl), 0, { hasCredentialCollection: true }, null, null, null, null, null, brands);
  assert.strictEqual(phantomPhish.action, 'block', `Phantom wallet phishing domain must be blocked! Got: ${phantomPhish.action}`);
});
