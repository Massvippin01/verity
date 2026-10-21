import test from 'node:test';
import assert from 'node:assert/strict';
import { queryCloudflareSecurityDoH, checkReputation } from '../background/reputation.js';
import { calculateRisk } from '../background/risk-engine.js';

test('Exfiltration Trap: Identifies Telegram and Discord webhook exfiltration endpoints', () => {
  const EXFIL_ENDPOINTS = [
    'api.telegram.org/bot',
    'discord.com/api/webhooks',
    'discordapp.com/api/webhooks',
    'webhook.site',
    'pipedream.net',
    'hookbin.com',
    'requestcatcher.com'
  ];

  function isExfilEndpoint(url) {
    if (!url || typeof url !== 'string') return false;
    const lower = url.toLowerCase();
    return EXFIL_ENDPOINTS.some(endpoint => lower.includes(endpoint));
  }

  // Common phishing kits exfiltrating stolen passwords
  assert.equal(isExfilEndpoint('https://api.telegram.org/bot123456:ABC-DEF/sendMessage?chat_id=123&text=victim'), true);
  assert.equal(isExfilEndpoint('https://discord.com/api/webhooks/1234567890/token-abc-xyz'), true);
  assert.equal(isExfilEndpoint('https://webhook.site/uuid-token-receiver'), true);
  assert.equal(isExfilEndpoint('https://my-catcher.pipedream.net/collect'), true);

  // Legitimate normal API endpoints must NOT be flagged
  assert.equal(isExfilEndpoint('https://api.github.com/repos/verity/project'), false);
  assert.equal(isExfilEndpoint('https://www.google.com/search?q=cybersecurity'), false);
  assert.equal(isExfilEndpoint('https://netbanking.hdfcbank.com/netbanking/entry'), false);
});

test('DoH Sentinel: queryCloudflareSecurityDoH handles sinkhole detection safely', async () => {
  // Verifies safe execution and non-crashing in test environments
  const result = await queryCloudflareSecurityDoH('test-domain.xyz');
  assert.equal(typeof result, 'object');
  assert.equal(typeof result.malware, 'boolean');
});

test('Zero-Day Defense: Runtime threat signal immediately produces critical BLOCK', () => {
  const targetUrl = 'https://fresh-zero-day-phish-kit-2026.xyz/login';
  const threatIntel = {
    malware: true,
    source: 'Cloudflare Global Threat Intelligence (1.1.1.2)'
  };

  const verdict = calculateRisk(
    targetUrl,
    [], // 0 initial rule signals
    null,
    null,
    threatIntel
  );

  assert.equal(verdict.action, 'block', 'Live threat hit must instantly trigger BLOCK');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85, `Score should be >= 85, got ${verdict.score}`);
  assert.equal(verdict.categories.malware.flagged, true);
});

test('Enterprise SSO Shield: Protects Okta, Azure B2C, and Google Workspace federated logins from false alarms', () => {
  const oktaSsoUrl = 'https://company.okta.com/oauth2/v1/authorize?client_id=0oa123456789&response_type=code&scope=openid&state=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ';
  
  const verdict = calculateRisk(
    oktaSsoUrl,
    [],
    null,
    null,
    null
  );

  assert.equal(verdict.action, 'allow', 'Genuine Okta SSO authentication must be allowed');
  assert.equal(verdict.score, 0, 'URL category points should be masked for valid IdP tokens');
});

test('Advanced Lexical Features: extractAdvancedFeatures returns 8 specialized signals', async () => {
  const { extractAdvancedFeatures } = await import('../background/rich-feature-extractor.js');
  const sampleUrl = 'https://sub1.sub2.banking-portal.xyz:8080/wp-content/plugins/auth/login.php?user=admin&token=abc_123%20test';
  
  const feats = extractAdvancedFeatures(sampleUrl, [{ name: 'HDFC Bank' }, { name: 'PayPal' }]);
  assert.equal(feats.length, 8, 'Advanced feature array should have exactly 8 elements');

  // [vowelConsonantRatio, brandMinDist, hasMixedScript, numSubdomains, sensitiveDirDepth, longestToken, specialCharDensity, isPortInUrl]
  const [vcr, bmd, hms, nsub, sdd, ltl, scd, port] = feats;
  assert.ok(vcr > 0, 'Vowel consonant ratio should be > 0');
  assert.equal(port, 1.0, 'Port 8080 should set is_port_in_url to 1.0');
  assert.ok(sdd >= 2, 'Should detect sensitive directory keywords (wp-content, plugins, auth, login)');
});

test('Anti-Cloaking: SIG_CANVAS_CREDENTIAL_FORM emits high risk on deceptive canvas forms', () => {
  const targetUrl = 'https://evasive-phish-kit.xyz/verify';
  const domSignals = {
    canvasCredentialLure: true
  };

  const verdict = calculateRisk(
    targetUrl,
    [],
    null,
    domSignals,
    null
  );

  assert.ok(verdict.score >= 55, `Risk score should be elevated for canvas lure, got: ${verdict.score}`);
  assert.ok(verdict.reasons.some(r => r.includes('canvas') || r.includes('Canvas')), 'Reasons should include canvas lure');
});

