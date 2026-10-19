import test from 'node:test';
import assert from 'node:assert/strict';
import { checkReputation, lookupThreatDatabase, ENABLE_REMOTE_THREAT_INTEL } from '../background/reputation.js';
import { calculateRisk } from '../background/risk-engine.js';

test('Threat Intelligence: is enabled and active', () => {
  assert.equal(ENABLE_REMOTE_THREAT_INTEL, true, 'Threat intelligence engine must be active');
});

test('Threat Intelligence: flags seed malicious domain', async () => {
  const result = await checkReputation('https://wigglepoploaderfast.monster/?540267a373b920a51ea99c645c7f');
  assert.equal(result.malware, true, 'Known malvertising domain must be flagged as malware');
  assert.ok(result.source && result.source.includes('URLhaus'), `Source should cite URLhaus, got: ${result.source}`);
});

test('Threat Intelligence: flags subdomains under a known malicious root domain', async () => {
  const result = await checkReputation('https://login.secure.paypa1-account-limited.com/account/auth');
  assert.equal(result.malware, true, 'Subdomain of known phishing domain must be flagged');
  assert.ok(result.source && result.source.includes('PhishTank'), `Source should cite PhishTank, got: ${result.source}`);
});

test('Threat Intelligence: allowlisted domains are NEVER flagged by threat intel', async () => {
  const googleResult = await checkReputation('https://www.google.com/search?q=test');
  assert.equal(googleResult.malware, false);
  assert.equal(googleResult.source, null);

  const sbiResult = await checkReputation('https://retail.onlinesbi.sbi/retail/login.htm');
  assert.equal(sbiResult.malware, false);
  assert.equal(sbiResult.source, null);
});

test('Threat Intelligence: unknown benign website returns clean verdict', async () => {
  const cleanResult = await checkReputation('https://my-personal-family-blog-2026.org/about');
  assert.equal(cleanResult.malware, false);
  assert.equal(cleanResult.source, null);
});

test('Threat Intelligence Integration: known malware immediately triggers BLOCK override in risk engine', async () => {
  const targetUrl = 'https://critical-security-alert-win.live/tech-support';
  const threatResult = await checkReputation(targetUrl);
  assert.equal(threatResult.malware, true);

  // Even with 0 rule signals and 0 DOM signals, threat intelligence alone MUST BLOCK
  const verdict = calculateRisk(
    targetUrl,
    [], // 0 rules
    null, // no ML
    null, // no DOM
    threatResult // Threat intelligence hit!
  );

  assert.equal(verdict.action, 'block', 'Threat intelligence hit must produce immediate BLOCK');
  assert.equal(verdict.severity, 'danger');
  assert.ok(verdict.score >= 85, `Risk score must be at least 85, got: ${verdict.score}`);
  assert.equal(verdict.categories.malware.flagged, true);
  assert.ok(verdict.reasons.some(r => r.includes('Threat Intelligence') || r.includes('threat intelligence') || r.includes('malware')), 'Reasons should include threat intel');
});
